import React from "react";
import { createRoot } from "react-dom/client";
import App from "./App.jsx";
import "./styles/index.css";
import { AuthProvider } from "./state/AuthContext.jsx";

createRoot(document.getElementById("root")).render(
  <React.StrictMode>
    <AuthProvider><App /></AuthProvider>
  </React.StrictMode>,
);
