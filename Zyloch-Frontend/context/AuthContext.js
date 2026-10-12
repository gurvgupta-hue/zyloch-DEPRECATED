"use client";
import React, { createContext, useContext, useState, useEffect } from "react";

const AuthContext = createContext();

export const AuthProvider = ({ children }) => {
  const [token, setToken] = useState(null);
  const [isAuthenticated, setIsAuthenticated] = useState(false);

  // --- Load token on mount ---
  useEffect(() => {
    if (typeof window !== "undefined") {
      const savedToken = localStorage.getItem("githubToken");
      setToken(savedToken);
      setIsAuthenticated(!!savedToken);

      // Sync across tabs
      const handleStorage = (e) => {
        if (e.key === "githubToken") {
          setToken(e.newValue);
          setIsAuthenticated(!!e.newValue);
        }
      };
      window.addEventListener("storage", handleStorage);
      return () => window.removeEventListener("storage", handleStorage);
    }
  }, []);

  // --- Auth actions ---
  const login = (newToken) => {
    if (typeof window !== "undefined") {
      localStorage.setItem("githubToken", newToken);
    }
    setToken(newToken);
    setIsAuthenticated(true);
  };

  const logout = () => {
    if (typeof window !== "undefined") {
      localStorage.removeItem("githubToken");
    }
    setToken(null);
    setIsAuthenticated(false);
  };

  const value = {
    token,
    isAuthenticated,
    login,
    logout,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) throw new Error("useAuth must be used inside AuthProvider");
  return context;
};
