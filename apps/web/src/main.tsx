import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter } from "react-router-dom";
import { AppRoutes } from "./App.js";
import "./styles.css";

const storedTheme = localStorage.getItem("himitsu-theme");
document.documentElement.dataset.theme = storedTheme === "light" ? "light" : "dark";

const root = document.getElementById("root");
if (root === null) throw new Error("Application root is missing");
createRoot(root).render(<StrictMode><BrowserRouter><AppRoutes /></BrowserRouter></StrictMode>);
