import React, { createContext, useContext, useState, useEffect } from "react";
import { ThemeProvider } from "@mui/material/styles";
import CssBaseline from "@mui/material/CssBaseline";
import { lightTheme, darkTheme } from "../utils/theme";

interface SettingsContextType {
  darkMode: boolean;
  compactMode: boolean;
  fontSize: "small" | "medium" | "large";
  animations: boolean;
  toggleDarkMode: () => void;
  toggleCompactMode: () => void;
  setFontSize: (size: "small" | "medium" | "large") => void;
  toggleAnimations: () => void;
}

const SettingsContext = createContext<SettingsContextType | undefined>(
  undefined
);

export const SettingsProvider: React.FC<{ children: React.ReactNode }> = ({
  children,
}) => {
  const [darkMode, setDarkMode] = useState(false);
  const [compactMode, setCompactMode] = useState(false);
  const [fontSize, setFontSize] = useState<"small" | "medium" | "large">(
    "medium"
  );
  const [animations, setAnimations] = useState(true);

  useEffect(() => {
    localStorage.setItem(
      "userSettings",
      JSON.stringify({ darkMode, compactMode, fontSize, animations })
    );
    document.documentElement.setAttribute(
      "data-theme",
      darkMode ? "dark" : "light"
    );

    const fontSizes = {
      small: "14px",
      medium: "16px",
      large: "18px",
    } as const;

    document.documentElement.style.fontSize = fontSizes[fontSize];
  }, [darkMode, compactMode, fontSize, animations]);

  const toggleDarkMode = () => setDarkMode((prev) => !prev);
  const toggleCompactMode = () => setCompactMode((prev) => !prev);
  const toggleAnimations = () => setAnimations((prev) => !prev);

  return (
    <SettingsContext.Provider
      value={{
        darkMode,
        compactMode,
        fontSize,
        animations,
        toggleDarkMode,
        toggleCompactMode,
        setFontSize,
        toggleAnimations,
      }}
    >
      <ThemeProvider theme={darkMode ? darkTheme : lightTheme}>
        <CssBaseline />
        {children}
      </ThemeProvider>
    </SettingsContext.Provider>
  );
};

export const useSettings = () => {
  const context = useContext(SettingsContext);
  if (!context) {
    throw new Error("useSettings must be used within a SettingsProvider");
  }
  return context;
};
