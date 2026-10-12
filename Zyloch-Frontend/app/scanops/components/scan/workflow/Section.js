import React from "react";

const Section = ({ title, subtitle, children }) => {
  return (
    <section className="bg-surface rounded-2xl shadow-2 p-6 border">
      <div className="mb-6">
        <h2 className="text-2xl font-bold text-text">{title}</h2>
        {subtitle && <p className="text-muted mt-2">{subtitle}</p>}
      </div>
      {children}
    </section>
  );
};

export default Section;