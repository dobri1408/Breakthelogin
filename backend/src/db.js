import pg from "pg";

const { Pool } = pg;

export const pool = new Pool({
  connectionString:
    process.env.DATABASE_URL ||
    "postgres://authx:authx@localhost:5432/authx_vulnerable"
});

export async function query(text, params) {
  return pool.query(text, params);
}

export async function logAudit({ userId = null, action, resource, resourceId = null, ipAddress }) {
  await query(
    `INSERT INTO audit_logs (user_id, action, resource, resource_id, ip_address)
     VALUES ($1, $2, $3, $4, $5)`,
    [userId, action, resource, resourceId, ipAddress]
  );
}
