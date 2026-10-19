import React, { lazy } from "react";
import { Routes, Route } from "react-router-dom";
import AdminUsers from "./AdminUsers";
import RequireAuth from "./RequireAuth";
const Billing = lazy(() => import("./Billing"));

function Home() {
  return fetch("/api/v1/feed").then(r => r.json());
}

function Profile() {
  fetch("/api/users/{id}/profile");
  return null;
}

export default function App() {
  return (
    <Routes>
      <Route path="/" element={<Home />} />
      <Route path="/login" element={<Login />} />
      <Route element={<RequireAuth />}>
        <Route path="/profile" element={<Profile />} />
        <Route path="/billing" element={<Billing />} />
        <Route path="/admin/users" element={<RequireAuth role="admin"><AdminUsers /></RequireAuth>} />
      </Route>
      <Route path="/admin/reports" element={<AdminReports />} />
    </Routes>
  );
}
function AdminReports() { return fetch("/api/admin/reports/export"); }
function Login() { return fetch("/api/auth/login", { method: "POST" }); }
