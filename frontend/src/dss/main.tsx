import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { DssApp } from "./DssApp";
import "./dss.css";

const root = document.getElementById("root");
if (!root) throw new Error("Missing application root");
createRoot(root).render(<StrictMode><DssApp /></StrictMode>);
