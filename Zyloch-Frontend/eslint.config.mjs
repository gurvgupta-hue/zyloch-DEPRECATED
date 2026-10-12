import nextVitals from "eslint-config-next/core-web-vitals";

const eslintConfig = [
  ...nextVitals,
  {
    ignores: ["node_modules/**", ".next/**", "dist/**", "build/**"],
  },
  {
    rules: {
      "react-hooks/exhaustive-deps": "warn",
      "no-unused-vars": "warn",
      "no-console": "off",
      "@next/next/no-img-element": "warn",
    },
  },
];

export default eslintConfig;
