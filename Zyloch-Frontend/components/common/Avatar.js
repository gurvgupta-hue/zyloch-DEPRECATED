// components/common/Avatar.js
export default function Avatar({
  src,
  alt,
  size = "md",
  fallback,
  className = "",
  ...props
}) {
  const sizes = {
    xs: "w-8 h-8 text-xs",
    sm: "w-10 h-10 text-sm",
    md: "w-12 h-12",
    lg: "w-16 h-16 text-lg",
    xl: "w-20 h-20 text-xl",
  };

  const containerClass = `
    rounded-full
    bg-elevated
    flex items-center justify-center
    font-medium
    overflow-hidden
    ${sizes[size]}
    ${className}
  `
    .trim()
    .replace(/\s+/g, " ");

  const imageClass = `
    w-full
    h-full
    object-cover
    rounded-full
    block
  `
    .trim()
    .replace(/\s+/g, " ");

  if (src) {
    return (
      <div className={containerClass} {...props}>
        <img
          src={src}
          alt={alt || "User avatar"}
          className={imageClass}
        />
      </div>
    );
  }

  const content =
    fallback || (alt ? alt.charAt(0).toUpperCase() : "U");

  return (
    <div
      className={containerClass}
      aria-label={alt || "User avatar"}
      role="img"
      {...props}
    >
      {content}
    </div>
  );
}
