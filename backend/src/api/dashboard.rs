//! Persönliches Dashboard-Layout. Der Aufbau der Widgets wird von der Weboberfläche
//! festgelegt, der Server speichert ihn nur (mit Größenbegrenzung).

use axum::{extract::State, Json};
use serde_json::{json, Value};

use crate::{
    auth::CurrentUser,
    error::{ApiError, ApiResult},
    AppState,
};

fn default_layout() -> Value {
    json!([
        { "type": "summary", "size": 3 },
        { "type": "down", "size": 1 },
        { "type": "events", "size": 2 },
        { "type": "status_chart", "size": 1 },
        { "type": "services", "size": 1 },
        { "type": "new", "size": 1 }
    ])
}

pub async fn load(State(st): State<AppState>, user: CurrentUser) -> ApiResult<Json<Value>> {
    let row: Option<(Value,)> = sqlx::query_as("SELECT layout FROM dashboards WHERE user_id = $1")
        .bind(user.id)
        .fetch_optional(&st.db)
        .await?;
    Ok(Json(row.map(|r| r.0).unwrap_or_else(default_layout)))
}

pub async fn save(
    State(st): State<AppState>,
    user: CurrentUser,
    Json(layout): Json<Value>,
) -> ApiResult<Json<Value>> {
    let widgets = layout
        .as_array()
        .ok_or_else(|| ApiError::BadRequest("Layout muss eine Liste von Widgets sein".into()))?;
    if widgets.len() > 50 || layout.to_string().len() > 32_000 {
        return Err(ApiError::BadRequest("Layout ist zu groß".into()));
    }
    sqlx::query(
        "INSERT INTO dashboards (user_id, layout) VALUES ($1, $2)
         ON CONFLICT (user_id) DO UPDATE SET layout = EXCLUDED.layout, updated_at = now()",
    )
    .bind(user.id)
    .bind(&layout)
    .execute(&st.db)
    .await?;
    Ok(Json(layout))
}
