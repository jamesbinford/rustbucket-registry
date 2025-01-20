use sqlx::{postgres::PgPool, Error};

pub async fn initialize_database(pool: &PgPool) -> Result<(), Error> {
    // Create admin users table
    sqlx::query!(
        r#"
        CREATE TABLE IF NOT EXISTS admin_users (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
        "#
    )
        .execute(pool)
        .await?;

    // Create rustbucket registrations table
    sqlx::query!(
        r#"
        CREATE TABLE IF NOT EXISTS rustbucket_registrations (
            id UUID PRIMARY KEY,
            token TEXT NOT NULL,
            hostname TEXT NOT NULL,
            instance_name TEXT,
            version TEXT NOT NULL,
            status TEXT NOT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            approved_at TIMESTAMPTZ,
            admin_notes TEXT
        )
        "#
    )
        .execute(pool)
        .await?;

    // Add any initial data if needed
    sqlx::query!(
        r#"
        INSERT INTO admin_users (username, password_hash, role)
        VALUES ($1, $2, $3)
        ON CONFLICT (username) DO NOTHING
        "#,
        "admin",
        "change-this-password-hash", // In production, use proper password hashing
        "admin"
    )
        .execute(pool)
        .await?;

    Ok(())
}

pub async fn reset_database(pool: &PgPool) -> Result<(), Error> {
    // Be very careful with this function! It deletes all data!
    sqlx::query!("DROP TABLE IF EXISTS rustbucket_registrations")
        .execute(pool)
        .await?;
    sqlx::query!("DROP TABLE IF EXISTS admin_users")
        .execute(pool)
        .await?;

    // Reinitialize tables
    initialize_database(pool).await?;

    Ok(())
}

// Example of a function to check database health
pub async fn check_database_health(pool: &PgPool) -> Result<bool, Error> {
    // Try a simple query to verify database connection
    let result = sqlx::query!("SELECT 1 as value")
        .fetch_one(pool)
        .await?;

    Ok(result.value == 1)
}