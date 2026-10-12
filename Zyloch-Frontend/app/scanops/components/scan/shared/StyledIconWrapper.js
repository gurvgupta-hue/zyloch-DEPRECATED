import React from "react";

const StyledIconWrapper = ({ children, color }) => (
  <span
    className="flex items-center justify-center w-6 h-6 transition-transform duration-300 group-hover:scale-110"
    style={{ color }}
  >
    {React.cloneElement(children, { className: "w-5 h-5" })}
  </span>
);

export default StyledIconWrapper;