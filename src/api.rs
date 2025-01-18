use axum::{
    extract::State,
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;
use time::OffsetDateTime;

#[derive(Debug, Serialize, Deserialize)]
pub struct RegistrationRequest {
    token: String,
    hostname: String,
    instance_name: Option<String>,
    version: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RegistrationResponse {
    status: String,
    registration_id: Uuid,
    message: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ApprovalRequest {
    registration_id: Uuid,
    approved: bool,
    admin_notes: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RegistrationStatus {
    registration_id: Uuid,
    status: String,
    created_at: OffsetDateTime,
    approved_at: Option<OffsetDateTime>,
    admin_notes: Option<String>,
}

async fn register_rustbucket(
    State(pool): State<PgPool>,
    Json(request): Json<RegistrationRequest>,
) -> Result<Json<RegistrationResponse>, (StatusCode, String)> {
    // Validate token format
    if !validate_token(&request.token) {
        return Err((
            StatusCode::BAD_REQUEST,
            "Invalid token format".to_string(),
        ));
    }

    // Generate a unique registration ID
    let registration_id = Uuid::new_v4();

    // Store registration attempt in database
    match sqlx::query!(
        r#"
        INSERT INTO rustbucket_registrations (
            id, token, hostname, instance_name, version, status, created_at
        )
        VALUES ($1, $2, $3, $4, $5, 'pending', NOW())
        "#,
        registration_id,
        request.token,
        request.hostname,
        request.instance_name,
        request.version,
    )
        .execute(&pool)
        .await
    {
        Ok(_) => Ok(Json(RegistrationResponse {
            status: "pending".to_string(),
            registration_id,
            message: "Registration request received and pending approval".to_string(),
        })),
        Err(e) => {
            eprintln!("Database error: {}", e);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to process registration".to_string(),
            ))
        }
    }
}

async fn get_registration_status(
    State(pool): State<PgPool>,
    registration_id: axum::extract::Path<Uuid>,
) -> Result<Json<RegistrationStatus>, (StatusCode, String)> {
    match sqlx::query_as!(
        RegistrationStatus,
        r#"
        SELECT
            id as registration_id,
            status,
            created_at,
            approved_at,
            admin_notes
        FROM rustbucket_registrations
        WHERE id = $1
        "#,
        registration_id.0
    )
        .fetch_optional(&pool)
        .await
    {
        Ok(Some(status)) => Ok(Json(status)),
        Ok(None) => Err((
            StatusCode::NOT_FOUND,
            "Registration not found".to_string(),
        )),
        Err(e) => {
            eprintln!("Database error: {}", e);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to fetch registration status".to_string(),
            ))
        }
    }
}

async fn approve_registration(
    State(pool): State<PgPool>,
    registration_id: axum::extract::Path<Uuid>,
    Json(request): Json<ApprovalRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    // TODO: Add admin authentication middleware

    match sqlx::query!(
        r#"
        UPDATE rustbucket_registrations
        SET
            status = CASE WHEN $1 THEN 'approved' ELSE 'rejected' END,
            approved_at = NOW(),
            admin_notes = $2
        WHERE id = $3
        "#,
        request.approved,
        request.admin_notes,
        registration_id.0,
    )
        .execute(&pool)
        .await
    {
        Ok(result) if result.rows_affected() == 0 => {
            Err((
                StatusCode::NOT_FOUND,
                "Registration not found".to_string(),
            ))
        }
        Ok(_) => Ok(StatusCode::OK),
        Err(e) => {
            eprintln!("Database error: {}", e);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to update registration status".to_string(),
            ))
        }
    }
}

fn validate_token(token: &str) -> bool {
    // TODO: Implement proper token validation
    // For now, just check if it's a non-empty string
    !token.is_empty()
}

pub async fn setup_database(pool: &PgPool) -> Result<(), sqlx::Error> {
    sqlx::query!(
        r#"
        CREATE TABLE IF NOT EXISTS rustbucket_registrations (
            id UUID PRIMARY KEY,
            token TEXT NOT NULL,
            hostname TEXT NOT NULL,
            instance_name TEXT,
            version TEXT NOT NULL,
            status TEXT NOT NULL,
            created_at TIMESTAMPTZ NOT NULL,
            approved_at TIMESTAMPTZ,
            admin_notes TEXT
        )
        "#
    )
        .execute(pool)
        .await?;

    Ok(())
}