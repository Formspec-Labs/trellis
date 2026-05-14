mod support;

use support::TestCluster;
use trellis_store_postgres_async::{MigrationError, run_migrations};

#[tokio::test]
async fn migrations_apply_idempotently() {
    let cluster = TestCluster::start_without_migrations();
    let pool = cluster.tls_pool(4).await;

    run_migrations(&pool).await.unwrap();
    run_migrations(&pool).await.unwrap();

    let versions: Vec<i32> =
        sqlx::query_scalar("SELECT version FROM trellis_schema_migrations ORDER BY version")
            .fetch_all(&pool)
            .await
            .unwrap();
    assert_eq!(versions, vec![1, 2, 3]);
}

#[tokio::test]
async fn forward_rollback_detected_when_schema_has_unknown_version() {
    let cluster = TestCluster::start_without_migrations();
    let pool = cluster.tls_pool(4).await;

    run_migrations(&pool).await.unwrap();
    sqlx::query("INSERT INTO trellis_schema_migrations (version) VALUES (99)")
        .execute(&pool)
        .await
        .unwrap();

    let error = run_migrations(&pool).await.unwrap_err();
    assert!(matches!(
        error,
        MigrationError::SchemaAhead {
            applied_version: 99,
            declared_max: 3
        }
    ));
}

#[tokio::test]
async fn concurrent_migration_runners_serialize_via_advisory_lock() {
    let cluster = TestCluster::start_without_migrations();
    let pool_a = cluster.tls_pool(4).await;
    let pool_b = cluster.tls_pool(4).await;

    let (a, b) = tokio::join!(run_migrations(&pool_a), run_migrations(&pool_b));
    a.unwrap();
    b.unwrap();

    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM trellis_schema_migrations")
        .fetch_one(&pool_a)
        .await
        .unwrap();
    assert_eq!(count, 3);
}
