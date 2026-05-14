mod support;

use sqlx::PgPool;
use support::TestCluster;
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

async fn started_pool() -> (TestCluster, PgPool) {
    let cluster = TestCluster::start_without_migrations();
    let pool = cluster.tls_pool(4).await;
    run_migrations(&pool).await.unwrap();
    (cluster, pool)
}

#[tokio::test]
async fn real_stored_event_round_trips_one_event() {
    let (_cluster, pool) = started_pool().await;
    let ev = event(
        b"scope-1",
        0,
        b"canonical-bytes",
        b"signed-bytes",
        b"idem-1",
    );

    let mut tx = pool.begin().await.unwrap();
    append_event_in_tx(&mut tx, &ev).await.unwrap();
    tx.commit().await.unwrap();

    let row: (Vec<u8>, i64, Vec<u8>, Vec<u8>, Option<Vec<u8>>) = sqlx::query_as(
        "\
SELECT scope, sequence, canonical_event, signed_event, idempotency_key \
FROM trellis_events WHERE scope = $1 AND sequence = $2",
    )
    .bind(b"scope-1".as_ref())
    .bind(0i64)
    .fetch_one(&pool)
    .await
    .unwrap();

    assert_eq!(row.0, b"scope-1");
    assert_eq!(row.1, 0);
    assert_eq!(row.2, b"canonical-bytes");
    assert_eq!(row.3, b"signed-bytes");
    assert_eq!(row.4.as_deref(), Some(b"idem-1".as_ref()));
}

#[tokio::test]
async fn idempotent_replay_same_payload_is_noop() {
    let (_cluster, pool) = started_pool().await;
    let ev = event(b"scope-replay", 0, b"canonical", b"signed", b"idem-replay");

    let mut tx = pool.begin().await.unwrap();
    append_event_in_tx(&mut tx, &ev).await.unwrap();
    tx.commit().await.unwrap();

    let mut tx = pool.begin().await.unwrap();
    append_event_in_tx(&mut tx, &ev).await.unwrap();
    tx.commit().await.unwrap();

    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM trellis_events WHERE scope = $1")
        .bind(b"scope-replay".as_ref())
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 1);
}

#[tokio::test]
async fn same_idempotency_key_different_payload_returns_mismatch() {
    let (_cluster, pool) = started_pool().await;
    let ev_a = event(b"scope-mismatch", 0, b"canonical-a", b"signed-a", b"idem");
    let ev_b = event(b"scope-mismatch", 1, b"canonical-b", b"signed-b", b"idem");

    let mut tx = pool.begin().await.unwrap();
    append_event_in_tx(&mut tx, &ev_a).await.unwrap();
    tx.commit().await.unwrap();

    let mut tx = pool.begin().await.unwrap();
    let err = append_event_in_tx(&mut tx, &ev_b).await.unwrap_err();
    tx.rollback().await.unwrap();

    assert!(matches!(err, AppendError::IdempotencyKeyPayloadMismatch));
}

#[tokio::test]
async fn pk_collision_without_idempotency_key_returns_pk_mismatch() {
    let (_cluster, pool) = started_pool().await;
    let ev_a = StoredEvent::new(
        b"scope-pk".to_vec(),
        0,
        b"canonical-a".to_vec(),
        b"signed-a".to_vec(),
    );
    let ev_b = StoredEvent::new(
        b"scope-pk".to_vec(),
        0,
        b"canonical-b".to_vec(),
        b"signed-b".to_vec(),
    );

    let mut tx = pool.begin().await.unwrap();
    append_event_in_tx(&mut tx, &ev_a).await.unwrap();
    tx.commit().await.unwrap();

    let mut tx = pool.begin().await.unwrap();
    let err = append_event_in_tx(&mut tx, &ev_b).await.unwrap_err();
    tx.rollback().await.unwrap();

    assert!(matches!(err, AppendError::PkCollisionMismatch));
}

#[tokio::test]
async fn sequence_gap_detected_for_non_genesis_hash_chain_event() {
    let (_cluster, pool) = started_pool().await;
    let ev = StoredEvent::new(
        b"scope-gap".to_vec(),
        1,
        b"canonical".to_vec(),
        b"signed".to_vec(),
    )
    .with_canonical_event_hash(Some([0xaa; 32]));

    let mut tx = pool.begin().await.unwrap();
    let err = append_event_in_tx(&mut tx, &ev).await.unwrap_err();
    tx.rollback().await.unwrap();

    assert!(matches!(err, AppendError::SequenceGap(0)));
}

#[tokio::test]
async fn idempotency_key_length_rejected_before_insert() {
    let (_cluster, pool) = started_pool().await;
    let ev = event(b"scope-long-key", 0, b"canonical", b"signed", &[0xab; 65]);

    let mut tx = pool.begin().await.unwrap();
    let err = append_event_in_tx(&mut tx, &ev).await.unwrap_err();
    tx.rollback().await.unwrap();

    assert!(matches!(err, AppendError::IdempotencyKeyTooLong(65)));
}
