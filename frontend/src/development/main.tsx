import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { DevelopmentApp } from "./DevelopmentApp";
import "./styles.css";

const root = document.getElementById("development-root");
if (!root) throw new Error("Missing development application root");

createRoot(root).render(
  <StrictMode>
    <DevelopmentApp />
  </StrictMode>,
);
