// Unified with the cyber background system (PR-10). Kept here for the existing
// import path (CyberHeroPanel + the ui barrel); the implementation lives in
// components/backgrounds. `intensity` is optional, so existing callers that
// pass only `className` are unaffected.
export { CyberGridBackground } from "../backgrounds/CyberBackgrounds";
