import{g}from"./index-D8ZSoNTM.js";function i(e,o){for(var n=0;n<o.length;n++){const r=o[n];if(typeof r!="string"&&!Array.isArray(r)){for(const t in r)if(t!=="default"&&!(t in e)){const a=Object.getOwnPropertyDescriptor(r,t);a&&Object.defineProperty(e,t,a.get?a:{enumerable:!0,get:()=>r[t]})}}}return Object.freeze(Object.defineProperty(e,Symbol.toStringTag,{value:"Module"}))}var c,d;function s(){if(d)return c;d=1,c=e,e.displayName="gcode",e.aliases=[];function e(o){o.languages.gcode={comment:/;.*|\B\(.*?\)\B/,string:{pattern:/"(?:""|[^"])*"/,greedy:!0},keyword:/\b[GM]\d+(?:\.\d+)?\b/,property:/\b[A-Z]/,checksum:{pattern:/(\*)\d+/,lookbehind:!0,alias:"number"},punctuation:/[:*]/}}return c}var u=s();const f=g(u),l=i({__proto__:null,default:f},[u]);export{l as g};