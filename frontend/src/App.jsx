import React, { useEffect, useMemo, useState } from "react";

const API_URL = import.meta.env.VITE_API_URL || "http://localhost:4000";

const auditLabels = {
  REGISTER: "S-a inscris",
  REGISTER_DUPLICATE: "A incercat register duplicat",
  LOGIN: "S-a logat",
  LOGIN_FAILED_PASSWORD: "A gresit parola",
  LOGIN_UNKNOWN_USER: "A incercat login cu user inexistent",
  LOGOUT: "A facut logout",
  RESET_TOKEN_CREATED: "A cerut resetare parola",
  RESET_UNKNOWN_USER: "A cerut resetare pentru email inexistent",
  PASSWORD_RESET: "A schimbat parola"
};

function describeAuditLog(log) {
  const actor = log.actor || log.email || log.resource_id || "necunoscut";
  const action = auditLabels[log.action] || log.action;

  return {
    actor,
    action,
    time: new Date(log.timestamp).toLocaleString("ro-RO"),
    details: `${log.resource} / ${log.resource_id || "fara id"}`,
    ipAddress: log.ip_address || "IP necunoscut"
  };
}

async function apiRequest(path, options = {}) {
  const token = localStorage.getItem("authx_token");
  const headers = {
    "Content-Type": "application/json",
    ...(options.headers || {})
  };

  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }

  const response = await fetch(`${API_URL}${path}`, {
    credentials: "include",
    ...options,
    headers
  });

  const data = await response.json().catch(() => ({}));

  if (!response.ok) {
    throw new Error(data.message || "Request esuat.");
  }

  return data;
}

export default function App() {
  const [activeTab, setActiveTab] = useState("login");
  const [message, setMessage] = useState("");
  const [user, setUser] = useState(null);
  const [auditLogs, setAuditLogs] = useState([]);
  const [resetToken, setResetToken] = useState("");

  const isLoggedIn = Boolean(user);
  const pageTitle = useMemo(
    () => (isLoggedIn ? "Zona interna AuthX" : "AuthX - autentificare"),
    [isLoggedIn]
  );

  useEffect(() => {
    apiRequest("/api/me")
      .then((data) => setUser(data.user))
      .catch(() => setUser(null));
  }, []);

  async function refreshAuditLogs() {
    const logsData = await apiRequest("/api/audit-logs");
    setAuditLogs(logsData.logs);
  }

  async function handleRegister(event) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const data = Object.fromEntries(form.entries());

    try {
      const result = await apiRequest("/api/auth/register", {
        method: "POST",
        body: JSON.stringify(data)
      });
      setMessage(result.message);
      event.currentTarget.reset();
      setActiveTab("login");
    } catch (error) {
      setMessage(error.message);
    }
  }

  async function handleLogin(event) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const data = Object.fromEntries(form.entries());

    try {
      const result = await apiRequest("/api/auth/login", {
        method: "POST",
        body: JSON.stringify(data)
      });
      // V1 vulnerabil: token-ul este tinut in localStorage, usor de furat prin XSS.
      localStorage.setItem("authx_token", result.token);
      setUser(result.user);
      setMessage(result.message);
      await refreshAuditLogs();
    } catch (error) {
      setMessage(error.message);
    }
  }

  async function handleLogout() {
    try {
      const result = await apiRequest("/api/auth/logout", { method: "POST" });
      localStorage.removeItem("authx_token");
      setUser(null);
      setAuditLogs([]);
      setMessage(result.message);
    } catch (error) {
      setMessage(error.message);
    }
  }

  async function handleForgotPassword(event) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const data = Object.fromEntries(form.entries());

    try {
      const result = await apiRequest("/api/auth/forgot-password", {
        method: "POST",
        body: JSON.stringify(data)
      });
      setResetToken(result.resetToken);
      setMessage(result.message);
    } catch (error) {
      setMessage(error.message);
    }
  }

  async function handleResetPassword(event) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const data = Object.fromEntries(form.entries());

    try {
      const result = await apiRequest("/api/auth/reset-password", {
        method: "POST",
        body: JSON.stringify(data)
      });
      setMessage(result.message);
      event.currentTarget.reset();
    } catch (error) {
      setMessage(error.message);
    }
  }

  return (
    <main className="app-shell">
      <section className="topbar">
        <div>
          <p className="eyebrow">Break the Login / v1</p>
          <h1>{pageTitle}</h1>
        </div>
        {isLoggedIn ? (
          <button className="ghost-button" onClick={handleLogout}>
            Logout
          </button>
        ) : null}
      </section>

      {message ? <p className="message">{message}</p> : null}

      {isLoggedIn ? (
        <Dashboard
          auditLogs={auditLogs}
          onRefresh={refreshAuditLogs}
          user={user}
        />
      ) : (
        <AuthForms
          activeTab={activeTab}
          onForgotPassword={handleForgotPassword}
          onLogin={handleLogin}
          onRegister={handleRegister}
          onResetPassword={handleResetPassword}
          resetToken={resetToken}
          setActiveTab={setActiveTab}
        />
      )}
    </main>
  );
}

function AuthForms({
  activeTab,
  onForgotPassword,
  onLogin,
  onRegister,
  onResetPassword,
  resetToken,
  setActiveTab
}) {
  return (
    <section className="auth-layout">
      <div className="panel">
        <div className="tabs">
          {["login", "register", "forgot", "reset"].map((tab) => (
            <button
              className={activeTab === tab ? "active" : ""}
              key={tab}
              onClick={() => setActiveTab(tab)}
              type="button"
            >
              {tab}
            </button>
          ))}
        </div>

        {activeTab === "login" ? (
          <form onSubmit={onLogin}>
            <label>
              Email
              <input name="email" placeholder="ana@authx.local" type="email" required />
            </label>
            <label>
              Parola
              <input name="password" placeholder="123" type="password" required />
            </label>
            <button type="submit">Login</button>
          </form>
        ) : null}

        {activeTab === "register" ? (
          <form onSubmit={onRegister}>
            <label>
              Email
              <input name="email" placeholder="ana@authx.local" type="email" required />
            </label>
            <label>
              Parola
              <input name="password" placeholder="merge si 1" type="password" required />
            </label>
            <label>
              Rol
              <select name="role" defaultValue="USER">
                <option value="USER">USER</option>
                <option value="ANALYST">ANALYST</option>
                <option value="MANAGER">MANAGER</option>
              </select>
            </label>
            <button type="submit">Creeaza cont</button>
          </form>
        ) : null}

        {activeTab === "forgot" ? (
          <form onSubmit={onForgotPassword}>
            <label>
              Email
              <input name="email" placeholder="ana@authx.local" type="email" required />
            </label>
            <button type="submit">Genereaza token reset</button>
            {resetToken ? (
              <div className="token-box">
                <span>Reset token returnat de API</span>
                <code>{resetToken}</code>
              </div>
            ) : null}
          </form>
        ) : null}

        {activeTab === "reset" ? (
          <form onSubmit={onResetPassword}>
            <label>
              Token
              <input name="token" defaultValue={resetToken} required />
            </label>
            <label>
              Parola noua
              <input name="newPassword" placeholder="oricat de slaba" type="password" required />
            </label>
            <button type="submit">Schimba parola</button>
          </form>
        ) : null}
      </div>

      <aside className="notes">
        <h2>Panou AuthX</h2>
        <ul>
          <li>Inregistreaza un cont nou.</li>
          <li>Autentifica-te cu email si parola.</li>
          <li>Testeaza fluxul de resetare parola.</li>
          <li>Verifica istoricul de audit dupa login.</li>
        </ul>
      </aside>
    </section>
  );
}

function Dashboard({
  auditLogs,
  onRefresh,
  user
}) {
  return (
    <section className="dashboard">
      <div className="identity-strip">
        <div>
          <span>Autentificat ca</span>
          <strong>{user.email}</strong>
        </div>
        <div>
          <span>Rol</span>
          <strong>{user.role}</strong>
        </div>
        <button className="ghost-button" onClick={onRefresh}>
          Refresh date
        </button>
      </div>

      <section className="panel">
        <div className="panel-heading">
          <div>
            <h2>Audit autentificare</h2>
            <p className="hint">In v1 orice utilizator autentificat vede toate evenimentele.</p>
          </div>
          <span className="count-pill">{auditLogs.length} evenimente</span>
        </div>
        <div className="audit-list">
          {auditLogs.map((log) => {
            const item = describeAuditLog(log);

            return (
              <article className="audit-item" key={log.id}>
                <div>
                  <span className="audit-action">{item.action}</span>
                  <strong>{item.actor}</strong>
                </div>
                <p>
                  {item.time} · {item.ipAddress}
                </p>
                <code>{item.details}</code>
              </article>
            );
          })}
          {auditLogs.length === 0 ? <p className="empty">Nu exista loguri.</p> : null}
        </div>
      </section>
    </section>
  );
}
