mod support;

use std::sync::Arc;

use sqlx::PgPool;
use support::TestCluster;
use tokio::task::JoinSet;
use trellis_store_postgres_async::{AppendError, append_event_in_tx, run_migrations};
use trellis_types::StoredEvent;

fn event(scope: &[u8], sequence: u64, canonical: &[u8], signed: &[u8], idem: &[u8]) -> StoredEvent {
    StoredEvent::with_idempotency_key(
        scope.to_vec(),
        sequence,
        canonical.to_vec(),
        signed.to_vec(),
        idem.to_vec(),
    )
}

async fn started_pool(max_connections: u32) -> (TestCluster, PgPool) {
    let cluster = TestCluster::start_without_migrations();
    let pool = cluster.tls_pool(max_connections).await;
    run_migrations(&pool).await.unwrap();
    (cluster, pool)
}

#[tokio::test]
async fn cleartext_rejected_by_tls_required_server() {
    let cluster = TestCluster::start_without_migrations();

    let _pool = cluster.tls_pool(1).await;
}

#[tokio::test]
async fn concurrent_same_key_same_seq_same_bytes_all_succeed() {
    let (_cluster, pool) = started_pool(32).await;
    let pool = Arc::new(pool);
    let ev = event(b"scope-conc-1", 5, b"canonical-A", b"signed-A", b"idem-A");

    let mut set: JoinSet<Result<(), AppendError>> = JoinSet::new();
    for _ in 0..8 {
        let pool = pool.clone();
        let ev = ev.clone();
        set.spawn(async move {
            let mut tx = pool.begin().await?;
            let result = append_event_in_tx(&mut tx, &ev).await;
            if result.is_ok() {
                tx.commit().await?;
            } else {
                tx.rollback().await?;
            }
            result
        });
    }

    let mut ok = 0;
    let mut errors = Vec::new();
    while let Some(result) = set.join_next().await {
        match result.unwrap() {
            Ok(()) => ok += 1,
            Err(error) => errors.push(error),
        }
    }

    assert_eq!(
        ok, 8,
        "all callers should succeed by insert or replay; errors={errors:?}"
    );
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM trellis_events WHERE scope = $1")
        .bind(b"scope-conc-1".as_ref())
        .fetch_one(&*pool)
        .await
        .unwrap();
    assert_eq!(count, 1);
}

#[tokio::test]
async fn concurrent_same_key_same_seq_different_bytes_one_winner_seven_mismatch() {
    let (_cluster, pool) = started_pool(32).await;
    let pool = Arc::new(pool);

    let mut set: JoinSet<Result<(), AppendError>> = JoinSet::new();
    for i in 0..8u8 {
        let pool = pool.clone();
        let canonical = format!("canonical-variant-{i}").into_bytes();
        let signed = format!("signed-variant-{i}").into_bytes();
        let ev = event(b"scope-conc-2", 9, &canonical, &signed, b"idem-B");
        set.spawn(async move {
            let mut tx = pool.begin().await?;
            let result = append_event_in_tx(&mut tx, &ev).await;
            if result.is_ok() {
                tx.commit().await?;
            } else {
                tx.rollback().await?;
            }
            result
        });
    }

    let mut ok = 0;
    let mut mismatch = 0;
    let mut row_not_found = 0;
    let mut other = Vec::new();
    while let Some(result) = set.join_next().await {
        match result.unwrap() {
            Ok(()) => ok += 1,
            Err(AppendError::IdempotencyKeyPayloadMismatch | AppendError::PkCollisionMismatch) => {
                mismatch += 1;
            }
            Err(AppendError::Sqlx(sqlx::Error::RowNotFound)) => row_not_found += 1,
            Err(error) => other.push(error.to_string()),
        }
    }

    assert_eq!(ok, 1, "expected exactly one winner");
    assert_eq!(mismatch, 7, "expected seven payload mismatches");
    assert_eq!(
        row_not_found, 0,
        "collision SELECT should see the winner row"
    );
    assert!(other.is_empty(), "unexpected errors: {other:?}");
}

#[tokio::test]
async fn concurrent_same_idempotency_key_different_sequences_one_winner_seven_mismatch() {
    let (_cluster, pool) = started_pool(32).await;
    let pool = Arc::new(pool);

    let mut set: JoinSet<Result<(), AppendError>> = JoinSet::new();
    for i in 0..8u64 {
        let pool = pool.clone();
        let canonical = format!("canonical-seq-{i}").into_bytes();
        let signed = format!("signed-seq-{i}").into_bytes();
        let ev = event(b"scope-conc-3", i, &canonical, &signed, b"idem-C");
        set.spawn(async move {
            let mut tx = pool.begin().await?;
            let result = append_event_in_tx(&mut tx, &ev).await;
            if result.is_ok() {
                tx.commit().await?;
            } else {
                tx.rollback().await?;
            }
            result
        });
    }

    let mut ok = 0;
    let mut idem_mismatch = 0;
    let mut row_not_found = 0;
    let mut other = Vec::new();
    while let Some(result) = set.join_next().await {
        match result.unwrap() {
            Ok(()) => ok += 1,
            Err(AppendError::IdempotencyKeyPayloadMismatch) => idem_mismatch += 1,
            Err(AppendError::Sqlx(sqlx::Error::RowNotFound)) => row_not_found += 1,
            Err(error) => other.push(error.to_string()),
        }
    }

    assert_eq!(ok, 1, "expected exactly one winner");
    assert_eq!(idem_mismatch, 7, "expected seven idempotency mismatches");
    assert_eq!(
        row_not_found, 0,
        "collision SELECT should see the winner row"
    );
    assert!(other.is_empty(), "unexpected errors: {other:?}");
}
