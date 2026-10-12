import React from 'react';
import * as SiIcons from 'react-icons/si';
import * as TbIcons from 'react-icons/tb';
import * as GoIcons from 'react-icons/go';
import * as VscIcons from 'react-icons/vsc';
import * as AiIcons from 'react-icons/ai';
import { FaVuejs, FaCode } from 'react-icons/fa';
import { FaAws } from 'react-icons/fa6';

// Default icon for unknown languages
export const CodeIcon = FaCode;

const fromSet = (iconSet, iconName, fallback = CodeIcon) => iconSet?.[iconName] || fallback;

const si = (iconName) => fromSet(SiIcons, iconName);
const tb = (iconName) => fromSet(TbIcons, iconName);
const go = (iconName) => fromSet(GoIcons, iconName);
const vsc = (iconName) => fromSet(VscIcons, iconName);
const ai = (iconName) => fromSet(AiIcons, iconName);

// Keep this map compact and robust: unknown/missing icon names fall back to CodeIcon.
export const languageIcons = {
    // JS/TS
    javascript: si('SiJavascript'),
    js: si('SiJavascript'),
    typescript: si('SiTypescript'),
    ts: si('SiTypescript'),

    // Frontend
    react: si('SiReact'),
    vue: FaVuejs,
    vuejs: FaVuejs,
    angular: si('SiAngular'),
    svelte: si('SiSvelte'),
    nextjs: si('SiNextdotjs'),
    nuxtjs: FaVuejs,
    remix: si('SiRemix'),
    astro: si('SiAstro'),

    // Backend & systems
    nodejs: si('SiNodedotjs'),
    node: si('SiNodedotjs'),
    express: si('SiExpress'),
    nestjs: si('SiNestjs'),
    python: si('SiPython'),
    py: si('SiPython'),
    java: si('SiJava'),
    c: si('SiC'),
    'c++': si('SiCplusplus'),
    cpp: si('SiCplusplus'),
    'c#': si('SiCsharp'),
    csharp: si('SiCsharp'),
    cs: si('SiCsharp'),
    php: si('SiPhp'),
    ruby: si('SiRuby'),
    go: si('SiGo'),
    golang: si('SiGo'),
    rust: si('SiRust'),
    swift: si('SiSwift'),
    kotlin: si('SiKotlin'),
    dart: si('SiDart'),
    scala: si('SiScala'),
    r: si('SiR'),

    // Markup & config
    html: si('SiHtml5'),
    html5: si('SiHtml5'),
    css: si('SiCss3'),
    css3: si('SiCss3'),
    markdown: si('SiMarkdown'),
    md: si('SiMarkdown'),
    json: si('SiJson'),
    yaml: si('SiYaml'),
    yml: si('SiYaml'),
    xml: go('GoFileCode'),
    toml: go('GoFileCode'),
    csv: go('GoFileCode'),

    // Shell
    shell: si('SiGnubash'),
    bash: si('SiGnubash'),
    sh: si('SiGnubash'),
    zsh: go('GoTerminal'),
    powershell: si('SiPowershell'),
    ps: si('SiPowershell'),

    // Data, cloud, infra
    graphql: si('SiGraphql'),
    mysql: si('SiMysql'),
    postgresql: si('SiPostgresql'),
    postgres: si('SiPostgresql'),
    mongodb: si('SiMongodb'),
    redis: si('SiRedis'),
    docker: si('SiDocker'),
    kubernetes: si('SiKubernetes'),
    aws: FaAws,
    gcp: si('SiGooglecloud'),
    azure: si('SiMicrosoftazure'),
    terraform: si('SiTerraform'),
    ansible: si('SiAnsible'),

    // Build & tooling
    git: si('SiGit'),
    githubactions: si('SiGithubactions'),
    npm: si('SiNpm'),
    yarn: si('SiYarn'),
    webpack: si('SiWebpack'),
    vite: si('SiVite'),
    babel: si('SiBabel'),
    eslint: si('SiEslint'),
    prettier: si('SiPrettier'),
    jest: si('SiJest'),
    cypress: si('SiCypress'),
    playwright: si('SiPlaywright'),

    // UI/CSS libs
    sass: si('SiSass'),
    scss: si('SiSass'),
    less: si('SiLess'),
    tailwindcss: si('SiTailwindcss'),
    bootstrap: si('SiBootstrap'),
    materialui: si('SiMaterialui'),
    chakraui: si('SiChakraui'),
    antdesign: si('SiAntdesign'),
    redux: si('SiRedux'),
    mobx: si('SiMobx'),
    firebase: si('SiFirebase'),
    supabase: si('SiSupabase'),

    // Office/doc
    pptx: tb('TbFileTypePptx'),
    doc: tb('TbFileTypeDoc'),
    docx: tb('TbFileTypeDoc'),
    pdf: tb('TbFileTypePdf'),
    txt: ai('AiOutlineFileText'),

    // Default
    default: CodeIcon,
    unknown: CodeIcon,
};

export const getLanguageIcon = (language) => {
    if (!language) return CodeIcon;

    const lang = String(language).toLowerCase().trim();

    if (languageIcons[lang]) {
        return languageIcons[lang];
    }

    if (lang.includes('javascript') || lang.includes('jsx') || lang.includes('tsx')) {
        return si('SiJavascript');
    }

    if (lang.includes('typescript')) {
        return si('SiTypescript');
    }

    if (lang.includes('python')) {
        return si('SiPython');
    }

    if (lang.includes('java') && !lang.includes('javascript')) {
        return si('SiJava');
    }

    if (lang.includes('html')) {
        return si('SiHtml5');
    }

    if (lang.includes('css')) {
        return si('SiCss3');
    }

    if (lang.includes('markdown')) {
        return si('SiMarkdown');
    }

    if (lang.includes('json')) {
        return si('SiJson');
    }

    if (lang.includes('yaml') || lang.includes('yml')) {
        return si('SiYaml');
    }

    if (lang.includes('shell') || lang.includes('bash') || lang.includes('zsh')) {
        return si('SiGnubash');
    }

    return CodeIcon;
};

export const LanguageIcon = ({ language, size = 20, className = '' }) => {
    const IconComponent = getLanguageIcon(language);
    return <IconComponent size={size} className={className} />;
};
