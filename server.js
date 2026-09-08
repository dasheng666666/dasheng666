const express = require("express");
const session = require("express-session");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const {
  S3Client,
  PutObjectCommand,
  GetObjectCommand,
  DeleteObjectCommand,
  HeadObjectCommand,
  PutBucketCorsCommand,
  CreateMultipartUploadCommand,
  UploadPartCommand,
  CompleteMultipartUploadCommand,
  AbortMultipartUploadCommand
} = require("@aws-sdk/client-s3");
const { getSignedUrl } = require("@aws-sdk/s3-request-presigner");

const app = express();
app.set("trust proxy", 1);

const PORT = process.env.PORT || 3000;
const MAX_UPLOAD_MB = Math.max(1, Number(process.env.MAX_UPLOAD_MB) || 1024);

const BUCKET_NAME = process.env.BUCKET || "";
const BUCKET_ENDPOINT = process.env.ENDPOINT || "";
const BUCKET_REGION = process.env.REGION || "auto";
const BUCKET_ACCESS_KEY = process.env.ACCESS_KEY_ID || "";
const BUCKET_SECRET_KEY = process.env.SECRET_ACCESS_KEY || "";
const BUCKET_READY = Boolean(
  BUCKET_NAME && BUCKET_ENDPOINT && BUCKET_ACCESS_KEY && BUCKET_SECRET_KEY
);

const s3 = BUCKET_READY ? new S3Client({
  region: BUCKET_REGION,
  endpoint: BUCKET_ENDPOINT,
  credentials: {
    accessKeyId: BUCKET_ACCESS_KEY,
    secretAccessKey: BUCKET_SECRET_KEY
  }
}) : null;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "change-me";
const INTERNAL_ACCESS_PASSWORD = process.env.INTERNAL_ACCESS_PASSWORD || process.env.INTERNAL_VIDEO_PASSWORD || "";
const SESSION_SECRET = process.env.SESSION_SECRET || "change-this-secret";
const STORAGE_ROOT = process.env.STORAGE_DIR || path.join(__dirname, "storage");
const DATA_FILE = path.join(STORAGE_ROOT, "documents.json");
const SETTINGS_FILE = path.join(STORAGE_ROOT, "site-settings.json");
const INTERNAL_RESOURCES_FILE = path.join(STORAGE_ROOT, "internal-resources.json");
const LEGACY_INTERNAL_VIDEOS_FILE = path.join(STORAGE_ROOT, "internal-videos.json");
const UPLOAD_DIR = path.join(STORAGE_ROOT, "uploads");

fs.mkdirSync(UPLOAD_DIR, { recursive: true });
if (!fs.existsSync(DATA_FILE)) fs.writeFileSync(DATA_FILE, "[]", "utf8");
if (!fs.existsSync(INTERNAL_RESOURCES_FILE)) {
  if (fs.existsSync(LEGACY_INTERNAL_VIDEOS_FILE)) {
    fs.copyFileSync(LEGACY_INTERNAL_VIDEOS_FILE, INTERNAL_RESOURCES_FILE);
  } else {
    fs.writeFileSync(INTERNAL_RESOURCES_FILE, "[]", "utf8");
  }
}

const DEFAULT_SETTINGS = {
  announcement: {
    enabled: true,
    title: "置顶公告",
    content: "欢迎使用人民邮电出版社工具包。"
  },
  submission: {
    enabled: true,
    title: "投稿邮箱",
    email: "",
    content: "投稿前请确认作品及资料完整，并按照要求发送至指定邮箱。"
  }
};

if (!fs.existsSync(SETTINGS_FILE)) {
  fs.writeFileSync(SETTINGS_FILE, JSON.stringify(DEFAULT_SETTINGS, null, 2), "utf8");
}

app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    maxAge: 1000 * 60 * 60 * 12
  }
}));

async function ensureBucketCors() {
  if (!BUCKET_READY) return;
  try {
    await s3.send(new PutBucketCorsCommand({
      Bucket: BUCKET_NAME,
      CORSConfiguration: {
        CORSRules: [{
          AllowedHeaders: ["*"],
          AllowedMethods: ["GET", "HEAD", "PUT"],
          AllowedOrigins: ["*"],
          ExposeHeaders: ["ETag"],
          MaxAgeSeconds: 3600
        }]
      }
    }));
    console.log("Bucket CORS 已就绪");
  } catch (err) {
    console.warn("Bucket CORS 自动配置未完成：", err?.message || err);
  }
}
ensureBucketCors();

function readDocs() {
  try { return JSON.parse(fs.readFileSync(DATA_FILE, "utf8")); }
  catch { return []; }
}
function writeDocs(docs) {
  fs.writeFileSync(DATA_FILE, JSON.stringify(docs, null, 2), "utf8");
}
function readInternalResources() {
  try { return JSON.parse(fs.readFileSync(INTERNAL_RESOURCES_FILE, "utf8")); }
  catch { return []; }
}
function writeInternalResources(items) {
  fs.writeFileSync(INTERNAL_RESOURCES_FILE, JSON.stringify(items, null, 2), "utf8");
}
function readSettings() {
  try {
    const current = JSON.parse(fs.readFileSync(SETTINGS_FILE, "utf8"));
    return {
      announcement: { ...DEFAULT_SETTINGS.announcement, ...(current.announcement || {}) },
      submission: { ...DEFAULT_SETTINGS.submission, ...(current.submission || {}) }
    };
  } catch {
    return JSON.parse(JSON.stringify(DEFAULT_SETTINGS));
  }
}
function writeSettings(settings) {
  fs.writeFileSync(SETTINGS_FILE, JSON.stringify(settings, null, 2), "utf8");
}
function clean(v, max=500) {
  return String(v || "").trim().slice(0, max);
}

function safeOriginalName(name) {
  return path.basename(String(name || "file")).replace(/[\r\n"]/g, "_").slice(0, 240);
}
function adminOnly(req, res, next) {
  if (req.session?.isAdmin) return next();
  res.status(401).json({ error: "未登录或登录已过期" });
}
function internalAccessOnly(req, res, next) {
  if (req.session?.internalAccess) return next();
  res.status(401).json({ error: "未获得内部资料访问权限" });
}

function classifyInternalResource(contentType, originalName) {
  const mime=String(contentType||"").toLowerCase();
  const ext=path.extname(String(originalName||"")).toLowerCase();
  if(mime.startsWith("video/") || [".mp4",".webm",".mov",".m4v",".mkv"].includes(ext)) return "video";
  if(mime.startsWith("audio/") || [".mp3",".wav",".m4a",".aac",".ogg",".flac"].includes(ext)) return "audio";
  if(mime.startsWith("image/") || [".jpg",".jpeg",".png",".gif",".webp",".bmp",".svg"].includes(ext)) return "image";
  if(mime==="application/pdf" || ext===".pdf") return "pdf";
  if(mime.startsWith("text/") || [".txt",".md",".csv",".json",".log"].includes(ext)) return "text";
  return "file";
}

function validHttpUrl(value) {
  try {
    const u = new URL(String(value || "").trim());
    return (u.protocol === "http:" || u.protocol === "https:") ? u.toString() : null;
  } catch {
    return null;
  }
}

const allowed = new Set([
  ".pdf",".doc",".docx",".ppt",".pptx",
  ".xls",".xlsx",".zip",".rar",".7z",".txt"
]);

const upload = multer({
  storage: multer.diskStorage({
    destination: (_, __, cb) => cb(null, UPLOAD_DIR),
    filename: (_, file, cb) => {
      const ext = path.extname(file.originalname).toLowerCase();
      cb(null, Date.now() + "-" + crypto.randomBytes(4).toString("hex") + ext);
    }
  }),
  limits: { fileSize: MAX_UPLOAD_MB * 1024 * 1024 },
  fileFilter: (_, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    allowed.has(ext) ? cb(null, true) : cb(new Error("不支持该文件类型"));
  }
});

const css = `
:root{
  --bg:#f5f7fb;--text:#101828;--muted:#667085;--line:#e4e7ec;
  --p:#5b5ff0;--p2:#8b5cf6;--danger:#d92d20;--ok:#027a48
}
*{box-sizing:border-box}
body{
  margin:0;font-family:Inter,"PingFang SC","Microsoft YaHei",system-ui,sans-serif;
  color:var(--text);
  background:
    radial-gradient(circle at 15% 10%,rgba(91,95,240,.13),transparent 28%),
    radial-gradient(circle at 85% 15%,rgba(139,92,246,.12),transparent 25%),
    var(--bg)
}
a{text-decoration:none;color:inherit}
button,input,textarea,select{font:inherit}
button{cursor:pointer}
.wrap{width:min(1160px,calc(100% - 32px));margin:auto}
.nav{height:72px;display:flex;align-items:center;justify-content:space-between}
.brand{font-weight:800;display:flex;align-items:center;gap:10px}
.logo{
  width:38px;height:38px;border-radius:12px;color:#fff;display:grid;place-items:center;
  background:linear-gradient(135deg,var(--p),var(--p2))
}
.hero{text-align:center;padding:70px 0 36px}
.hero h1{font-size:clamp(38px,6vw,66px);line-height:1.05;margin:15px 0}
.hero p{color:var(--muted);font-size:16px;line-height:1.8}
.tag{
  display:inline-block;background:#fff;border:1px solid var(--line);
  border-radius:999px;padding:8px 12px;color:#475467;font-size:13px
}
.tools{max-width:800px;margin:28px auto 0;display:grid;grid-template-columns:1fr 180px;gap:10px}
input,textarea,select{
  width:100%;border:1px solid #d0d5dd;border-radius:12px;padding:12px 13px;
  background:#fff;outline:none
}
textarea{min-height:110px;resize:vertical}
input:focus,textarea:focus,select:focus{
  border-color:#9b9ef8;box-shadow:0 0 0 4px rgba(91,95,240,.08)
}
.grid{display:grid;grid-template-columns:repeat(3,1fr);gap:18px;padding:20px 0 60px}
.card{
  background:rgba(255,255,255,.92);border:1px solid var(--line);border-radius:20px;
  padding:20px;box-shadow:0 18px 55px rgba(16,24,40,.07);
  display:flex;flex-direction:column;min-height:250px
}
.file{
  width:50px;height:50px;border-radius:15px;display:grid;place-items:center;
  background:rgba(91,95,240,.1);color:var(--p);font-weight:800
}
.badge{font-size:12px;color:#475467;background:#f2f4f7;padding:5px 9px;border-radius:999px}
.row{display:flex;justify-content:space-between;align-items:center;gap:12px}
.card h3{font-size:18px;margin:17px 0 8px}
.desc{font-size:14px;line-height:1.7;color:var(--muted)}
.meta{font-size:12px;color:#98a2b3;margin-top:auto;padding-top:15px}
.btn{
  display:inline-flex;justify-content:center;align-items:center;border:0;border-radius:12px;
  padding:11px 14px;background:linear-gradient(135deg,var(--p),var(--p2));
  color:#fff;font-weight:700
}
.card .btn{margin-top:13px}
.empty{
  grid-column:1/-1;padding:50px;text-align:center;color:var(--muted);
  background:#fff;border:1px dashed #d0d5dd;border-radius:18px
}
.notice-board{
  margin:12px 0 18px;padding:18px 20px;border-radius:18px;
  background:linear-gradient(135deg,rgba(255,248,225,.98),rgba(255,252,242,.98));
  border:1px solid #f4d98a;box-shadow:0 14px 42px rgba(146,105,16,.08)
}
.notice-board .notice-title{
  display:flex;align-items:center;gap:8px;margin:0 0 8px;
  font-size:16px;font-weight:800;color:#7a5310
}
.notice-board .notice-content{
  color:#6b5a35;line-height:1.75;font-size:14px;white-space:pre-wrap
}
.submission-box{
  margin:0 0 22px;padding:20px;border-radius:18px;background:#fff;
  border:1px solid var(--line);box-shadow:0 14px 42px rgba(16,24,40,.06);
  display:grid;grid-template-columns:1fr auto;gap:18px;align-items:center
}
.submission-box h3{margin:0 0 7px;font-size:17px}
.submission-box p{margin:0;color:var(--muted);font-size:14px;line-height:1.7;white-space:pre-wrap}
.email-link{
  display:inline-flex;align-items:center;justify-content:center;min-width:190px;
  padding:11px 15px;border-radius:12px;border:1px solid #c7c9ff;
  background:#f7f7ff;color:#4548ce;font-weight:700;word-break:break-all
}
.settings-grid{
  display:grid;grid-template-columns:1fr 1fr;gap:18px
}
.settings-card{
  border:1px solid var(--line);border-radius:16px;padding:18px;background:#fbfcfe
}
.switch-row{
  display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:14px
}
.switch-row input[type="checkbox"]{width:18px;height:18px}


/* ===== V2：首页重新设计（仅前台） ===== */
.home-page{
  min-height:100vh;
  background:
    radial-gradient(circle at 8% -5%,rgba(77,91,214,.12),transparent 28%),
    radial-gradient(circle at 92% 8%,rgba(119,91,214,.09),transparent 24%),
    #f6f7fb;
}
.home-wrap{width:min(1180px,calc(100% - 32px));margin:auto}
.home-nav{
  height:76px;display:flex;align-items:center;justify-content:space-between;
  border-bottom:1px solid rgba(228,231,236,.8)
}
.home-brand{display:flex;align-items:center;gap:12px;font-size:17px;font-weight:850;letter-spacing:.01em}
.home-brand-mark{
  width:40px;height:40px;border-radius:12px;display:grid;place-items:center;
  color:#fff;font-weight:900;background:linear-gradient(145deg,#263d87,#6556d8);
  box-shadow:0 10px 26px rgba(65,73,172,.2)
}
.home-admin-link{
  color:#475467;font-size:13px;padding:9px 12px;border:1px solid #e4e7ec;
  background:rgba(255,255,255,.82);border-radius:10px
}
.home-hero{
  margin-top:28px;padding:42px 44px 38px;border:1px solid #e5e7ee;
  border-radius:26px;background:rgba(255,255,255,.92);
  box-shadow:0 22px 70px rgba(26,35,71,.08);
  display:grid;grid-template-columns:minmax(0,1fr) 310px;gap:34px;align-items:center
}
.home-kicker{
  display:inline-flex;align-items:center;gap:7px;padding:7px 11px;border-radius:999px;
  background:#f0f2ff;color:#4147a8;font-size:12px;font-weight:750
}
.home-hero h1{
  margin:16px 0 13px;font-size:clamp(34px,5vw,54px);line-height:1.08;
  letter-spacing:-.035em;color:#101828
}
.home-hero p{margin:0;color:#667085;font-size:15px;line-height:1.85;max-width:700px}
.hero-side{
  padding:22px;border-radius:20px;background:linear-gradient(145deg,#172554,#35318f);
  color:#fff;min-height:180px;display:flex;flex-direction:column;justify-content:space-between
}
.hero-side strong{font-size:14px}
.hero-side .big{font-size:30px;font-weight:900;letter-spacing:-.03em}
.hero-side .small{font-size:12px;line-height:1.7;color:rgba(255,255,255,.72)}
.home-search{
  margin-top:18px;display:grid;grid-template-columns:minmax(0,1fr) 190px;gap:10px
}
.home-search input,.home-search select{
  min-height:48px;border-radius:13px;border:1px solid #dfe3ea;background:#fff
}
.front-section{margin-top:24px}
.front-section-head{
  display:flex;align-items:flex-end;justify-content:space-between;gap:16px;margin-bottom:14px
}
.front-section-head h2{margin:0;font-size:21px;letter-spacing:-.02em}
.front-section-head p{margin:4px 0 0;color:#98a2b3;font-size:12px}
.resource-grid{
  display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:16px
}
.resource-card{
  position:relative;background:#fff;border:1px solid #e5e7ec;border-radius:18px;
  padding:18px;box-shadow:0 12px 38px rgba(16,24,40,.055);
  display:flex;flex-direction:column;min-height:285px;transition:.18s ease
}
.resource-card:hover{transform:translateY(-2px);box-shadow:0 18px 48px rgba(16,24,40,.09)}
.resource-top{display:flex;justify-content:space-between;gap:12px;align-items:flex-start}
.resource-icon{
  width:46px;height:46px;border-radius:13px;display:grid;place-items:center;
  background:#f0f2ff;color:#4b50b8;font-size:12px;font-weight:900
}
.resource-badges{display:flex;gap:5px;flex-wrap:wrap;justify-content:flex-end}
.resource-badge{
  padding:5px 8px;border-radius:999px;background:#f2f4f7;color:#475467;
  font-size:11px;font-weight:700
}
.resource-badge.pin{background:#fff5d9;color:#865b00}
.resource-badge.rec{background:#eaf7ef;color:#18794e}
.resource-badge.link{background:#eef4ff;color:#3538cd}
.resource-card h3{font-size:17px;line-height:1.45;margin:15px 0 7px}
.resource-desc{
  color:#667085;font-size:13px;line-height:1.72;display:-webkit-box;
  -webkit-line-clamp:3;-webkit-box-orient:vertical;overflow:hidden
}
.resource-meta{
  display:grid;grid-template-columns:1fr 1fr;gap:7px;margin-top:auto;padding-top:16px;
  color:#98a2b3;font-size:11px
}
.resource-meta span:nth-child(even){text-align:right}
.resource-actions{display:flex;gap:8px;margin-top:13px}
.resource-actions .btn{flex:1;margin:0;padding:10px 12px;font-size:13px}
.preview-btn{
  flex:1;border:1px solid #d8dbe7;border-radius:11px;background:#fff;color:#344054;
  padding:10px 12px;font-weight:700
}
.recommended-shell{
  padding:18px;border-radius:22px;border:1px solid #e5e7ec;
  background:linear-gradient(145deg,rgba(245,247,255,.98),rgba(255,255,255,.98))
}
.front-notice-row{display:grid;grid-template-columns:1.35fr .9fr;gap:14px;margin-top:18px}
.front-notice-row .notice-board,.front-notice-row .submission-box{margin:0;height:100%}
.front-notice-row .submission-box{grid-template-columns:1fr}
.front-notice-row .email-link{min-width:0;width:100%}
.preview-mask{
  position:fixed;inset:0;background:rgba(16,24,40,.62);backdrop-filter:blur(5px);
  display:grid;place-items:center;padding:18px;z-index:1200
}
.preview-dialog{
  width:min(1050px,100%);height:min(84vh,860px);background:#fff;border-radius:20px;
  overflow:hidden;display:flex;flex-direction:column;box-shadow:0 34px 110px rgba(0,0,0,.28)
}
.preview-head{
  height:58px;display:flex;align-items:center;justify-content:space-between;
  padding:0 16px 0 20px;border-bottom:1px solid #e5e7ec
}
.preview-head strong{font-size:14px}
.preview-frame{border:0;width:100%;height:100%;background:#f5f6f8}
.home-footer{
  margin-top:34px;padding:25px 0 34px;border-top:1px solid #e5e7ec;
  color:#98a2b3;font-size:12px;display:flex;justify-content:space-between;gap:18px
}

/* ===== V2：后台资料元数据 ===== */
.admin-meta-grid{
  display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:10px;margin-top:8px
}
.admin-meta-chip{
  padding:7px 9px;border-radius:9px;background:#f8f9fc;color:#667085;font-size:11px
}
.recommend-chip{background:#eaf7ef!important;color:#18794e!important}
.edit-two{display:grid;grid-template-columns:1fr 1fr;gap:12px}

@media(max-width:900px){
  .home-hero{grid-template-columns:1fr}
  .hero-side{min-height:145px}
  .resource-grid{grid-template-columns:repeat(2,minmax(0,1fr))}
  .front-notice-row{grid-template-columns:1fr}
}
@media(max-width:620px){
  .home-hero{padding:28px 22px}
  .home-search,.resource-grid{grid-template-columns:1fr}
  .home-footer{flex-direction:column}
  .admin-meta-grid,.edit-two{grid-template-columns:1fr 1fr}
}

/* ===== 内部资料中心 ===== */
.internal-page{
  min-height:100vh;background:
    radial-gradient(circle at 8% -6%,rgba(59,67,170,.15),transparent 28%),
    radial-gradient(circle at 92% 7%,rgba(121,82,203,.11),transparent 24%),
    #f5f7fb
}
.internal-shell{width:min(1180px,calc(100% - 32px));margin:auto;padding-bottom:42px}
.internal-nav{
  height:76px;display:flex;align-items:center;justify-content:space-between;
  border-bottom:1px solid rgba(228,231,236,.86)
}
.internal-brand{display:flex;align-items:center;gap:12px;font-size:17px;font-weight:850}
.internal-mark{
  width:40px;height:40px;border-radius:12px;display:grid;place-items:center;color:#fff;
  font-weight:900;background:linear-gradient(145deg,#172554,#6153c5)
}
.internal-hero{
  margin:28px 0 18px;padding:34px;border-radius:24px;color:#fff;
  background:linear-gradient(140deg,#111a3c,#303477 60%,#674bb1);
  box-shadow:0 22px 60px rgba(24,31,76,.16)
}
.internal-hero h1{margin:8px 0 10px;font-size:clamp(30px,5vw,48px)}
.internal-hero p{margin:0;color:rgba(255,255,255,.74);line-height:1.8;font-size:14px}
.internal-toolbar{display:grid;grid-template-columns:1fr 220px;gap:10px;margin:18px 0}
.internal-toolbar input,.internal-toolbar select{min-height:48px}
.internal-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:17px}
.internal-card{
  overflow:hidden;border-radius:19px;background:#fff;border:1px solid #e5e7ec;
  box-shadow:0 13px 42px rgba(16,24,40,.06);display:flex;flex-direction:column;
  transition:.18s ease
}
.internal-card:hover{transform:translateY(-2px);box-shadow:0 20px 52px rgba(16,24,40,.1)}
.internal-cover{
  position:relative;aspect-ratio:16/9;display:grid;place-items:center;overflow:hidden;
  background:
    radial-gradient(circle at 25% 25%,rgba(124,112,255,.34),transparent 30%),
    linear-gradient(145deg,#121936,#343778 68%,#5d4ba9);
  color:#fff
}
.internal-cover-img{
  position:absolute;inset:0;width:100%;height:100%;object-fit:cover;display:block;z-index:1
}
.internal-cover-shade{
  position:absolute;inset:0;z-index:1;
  background:linear-gradient(to bottom,rgba(8,12,28,.04),rgba(8,12,28,.16));
  pointer-events:none
}
.internal-type,.internal-pin,.internal-file-icon{z-index:2}
.internal-file-icon{
  min-width:64px;height:64px;padding:0 12px;border-radius:17px;display:grid;place-items:center;
  background:rgba(255,255,255,.14);border:1px solid rgba(255,255,255,.28);
  backdrop-filter:blur(8px);font-size:15px;font-weight:900
}
.internal-type{
  position:absolute;left:13px;top:13px;padding:5px 8px;border-radius:999px;
  background:rgba(7,12,28,.5);font-size:11px
}
.internal-pin{
  position:absolute;right:13px;top:13px;padding:5px 8px;border-radius:999px;
  background:#fff3cd;color:#7c560c;font-size:11px;font-weight:700
}
.internal-card-body{padding:16px;display:flex;flex-direction:column;flex:1}
.internal-card h3{margin:0 0 7px;font-size:16px;line-height:1.45}
.internal-card p{
  margin:0;color:#667085;font-size:12px;line-height:1.7;min-height:41px;
  display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden
}
.internal-meta{display:flex;justify-content:space-between;gap:10px;color:#98a2b3;font-size:11px;margin-top:13px}
.internal-actions{display:flex;gap:8px;margin-top:auto;padding-top:13px}
.internal-actions .mini,.internal-actions .btn{flex:1;text-align:center}
.internal-login-wrap{
  min-height:100vh;display:grid;place-items:center;padding:24px;
  background:
    radial-gradient(circle at 18% 8%,rgba(70,78,190,.16),transparent 28%),
    #f5f7fb
}
.internal-login-card{
  width:min(460px,100%);padding:28px;border:1px solid #e4e7ec;border-radius:22px;
  background:#fff;box-shadow:0 24px 80px rgba(16,24,40,.1)
}
.internal-login-card h1{margin:18px 0 8px;font-size:30px}
.internal-login-card p{color:#667085;font-size:13px;line-height:1.7}
.internal-view-mask{
  position:fixed;inset:0;background:rgba(7,12,28,.82);backdrop-filter:blur(6px);
  display:grid;place-items:center;padding:18px;z-index:1500
}
.internal-view-dialog{
  width:min(1120px,100%);max-height:92vh;background:#0b1020;border-radius:18px;
  overflow:hidden;box-shadow:0 35px 110px rgba(0,0,0,.42);display:flex;flex-direction:column
}
.internal-view-head{
  min-height:58px;padding:12px 16px 12px 20px;display:flex;align-items:center;
  justify-content:space-between;color:#fff;border-bottom:1px solid rgba(255,255,255,.1)
}
.internal-video{display:block;width:100%;max-height:80vh;background:#000}
.internal-audio{width:calc(100% - 40px);margin:40px 20px}
.internal-image{display:block;max-width:100%;max-height:80vh;margin:auto;object-fit:contain;background:#111827}
.internal-frame{width:100%;height:78vh;border:0;background:#fff}
.internal-empty{
  grid-column:1/-1;padding:60px 20px;text-align:center;color:#667085;
  border:1px dashed #d0d5dd;background:#fff;border-radius:18px
}

/* 后台内部资料 */
.internal-admin-head{display:flex;justify-content:space-between;gap:16px;align-items:flex-start}
.internal-admin-list{margin-top:16px}
.internal-admin-item{
  display:grid;grid-template-columns:1fr auto;gap:18px;align-items:center;
  padding:16px;border:1px solid #e4e7ec;border-radius:14px;margin-top:10px
}
.internal-admin-item h3{margin:0 0 6px;font-size:16px}
.internal-admin-item p{margin:0;color:#98a2b3;font-size:12px}
.internal-progress{
  height:8px;background:#eef0f5;border-radius:999px;overflow:hidden;margin-top:9px
}
.internal-progress > span{
  display:block;height:100%;width:0;background:linear-gradient(90deg,#5b5ff0,#8b5cf6)
}
@media(max-width:900px){.internal-grid{grid-template-columns:repeat(2,1fr)}}
@media(max-width:620px){
  .internal-grid,.internal-toolbar{grid-template-columns:1fr}
  .internal-admin-item{grid-template-columns:1fr}
  .internal-hero{padding:26px 22px}
}

/* admin */
.admin{width:min(1050px,calc(100% - 32px));margin:40px auto}
.panel{
  background:#fff;border:1px solid var(--line);border-radius:20px;padding:22px;
  margin-bottom:18px;box-shadow:0 16px 50px rgba(16,24,40,.06)
}
.login{max-width:450px;margin:12vh auto}
.form{display:grid;grid-template-columns:1fr 1fr;gap:14px}
.full{grid-column:1/-1}
label{display:block;font-size:13px;color:#475467;margin-bottom:7px}
.notice{font-size:13px;color:var(--muted)}
.err{font-size:13px;color:var(--danger);margin-top:9px}
.ok{font-size:13px;color:var(--ok);margin-top:9px}
.hidden{display:none!important}
.item{
  display:grid;grid-template-columns:1fr auto;gap:18px;align-items:center;
  padding:16px;border:1px solid var(--line);border-radius:14px;margin-top:10px
}
.item h3{margin:0 0 6px;font-size:16px}
.item .admin-desc{
  margin:6px 0 0;color:var(--muted);font-size:13px;line-height:1.65;
  max-width:690px;white-space:pre-wrap
}
.item p{margin:0;color:#98a2b3;font-size:12px}
.mini{
  border:1px solid var(--line);background:#fff;border-radius:9px;
  padding:8px 11px;cursor:pointer
}
.mini.primary{color:var(--p);border-color:#c7c9ff;background:#f7f7ff}
.danger{color:var(--danger)}
.actions{display:flex;gap:7px;flex-wrap:wrap;justify-content:flex-end}

/* edit modal */
.modal-mask{
  position:fixed;inset:0;background:rgba(16,24,40,.52);backdrop-filter:blur(5px);
  display:grid;place-items:center;padding:20px;z-index:999
}
.modal{
  width:min(680px,100%);background:#fff;border-radius:22px;padding:24px;
  box-shadow:0 30px 90px rgba(16,24,40,.25)
}
.modal-head{display:flex;justify-content:space-between;align-items:center;margin-bottom:20px}
.modal-head h2{margin:0;font-size:22px}
.close-btn{
  width:36px;height:36px;border:1px solid var(--line);background:#fff;
  border-radius:10px;font-size:20px;line-height:1
}
.modal-actions{display:flex;justify-content:flex-end;gap:10px;margin-top:18px}
.secondary{
  border:1px solid var(--line);background:#fff;color:#344054;
  border-radius:12px;padding:11px 16px
}
.file-lock{
  padding:12px 14px;border-radius:12px;background:#f8f9fc;
  border:1px solid var(--line);font-size:13px;color:#667085
}

@media(max-width:850px){.grid{grid-template-columns:repeat(2,1fr)}}
@media(max-width:600px){
  .grid{grid-template-columns:1fr}
  .tools,.form,.settings-grid{grid-template-columns:1fr}
  .submission-box{grid-template-columns:1fr}
  .email-link{width:100%}
  .full{grid-column:auto}
  .item{grid-template-columns:1fr}
  .actions{justify-content:flex-start}
  .hero{padding-top:45px}
}
`;

const homeHtml = `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>人民邮电出版社工具包</title>
<style>${css}</style>
</head>
<body class="home-page">
<div class="home-wrap">
  <nav class="home-nav">
    <div class="home-brand"><span class="home-brand-mark">邮</span>人民邮电出版社工具包</div>
    <a class="home-admin-link" href="/admin.html">管理员入口</a>
  </nav>

  <header class="home-hero">
    <div>
      <span class="home-kicker">人民邮电出版社 · AI学习配套资源</span>
      <h1>资料、工具与课程配套资源，一站获取</h1>
      <p>集中管理课程文档、模板、工具入口与更新资源。支持大文件下载、工具直达、资料检索与在线预览。</p>
      <div class="home-search">
        <input id="q" placeholder="搜索资料名称、简介或分类">
        <select id="cat"><option value="">全部分类</option></select>
      </div>
    </div>
    <div class="hero-side">
      <strong>资源中心</strong>
      <div class="big" id="heroCount">0 份资料</div>
      <div class="small" id="heroSub">文件与工具统一管理，持续更新课程配套内容。</div>
    </div>
  </header>

  <div class="front-notice-row">
    <section id="announcementBox" class="notice-board hidden">
      <div class="notice-title">📌 <span id="announcementTitle">置顶公告</span></div>
      <div id="announcementContent" class="notice-content"></div>
    </section>

    <section id="submissionBox" class="submission-box hidden">
      <div>
        <h3 id="submissionTitle">投稿邮箱</h3>
        <p id="submissionContent"></p>
      </div>
      <a id="submissionEmail" class="email-link" href="#"></a>
    </section>
  </div>

  <section id="recommendedSection" class="front-section hidden">
    <div class="front-section-head">
      <div>
        <h2>推荐资源</h2>
        <p>后台标记为推荐的重点资料与工具</p>
      </div>
    </div>
    <div class="recommended-shell">
      <div id="recommendedGrid" class="resource-grid"></div>
    </div>
  </section>

  <section class="front-section">
    <div class="front-section-head">
      <div>
        <h2>全部资料与工具</h2>
        <p>支持搜索、分类筛选、下载与在线预览</p>
      </div>
      <span id="count" class="notice"></span>
    </div>
    <main class="resource-grid" id="grid"></main>
  </section>

  <footer class="home-footer">
    <span>人民邮电出版社工具包</span>
    <span>课程资料 · 工具资源 · 持续更新</span>
  </footer>
</div>

<div id="previewMask" class="preview-mask hidden">
  <div class="preview-dialog">
    <div class="preview-head">
      <strong id="previewTitle">在线预览</strong>
      <button id="previewClose" class="close-btn" type="button">×</button>
    </div>
    <iframe id="previewFrame" class="preview-frame" title="在线预览"></iframe>
  </div>
</div>

<script>
let docs=[];
const E=s=>String(s||"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#039;"}[c]));
function sz(b=0){
  if(!b)return "—";
  return b<1024?b+" B":b<1048576?(b/1024).toFixed(1)+" KB":b<1073741824?(b/1048576).toFixed(1)+" MB":(b/1073741824).toFixed(2)+" GB";
}
function dt(v){
  if(!v)return "—";
  const d=new Date(v);
  if(Number.isNaN(d.getTime()))return "—";
  return d.getFullYear()+"-"+String(d.getMonth()+1).padStart(2,"0")+"-"+String(d.getDate()).padStart(2,"0");
}
function canPreview(d){
  if(d.kind==="link")return false;
  const t=String(d.type||"").toUpperCase();
  return t==="PDF"||t==="TXT";
}
function card(d){
  const badges=
    (d.pinned?'<span class="resource-badge pin">置顶</span>':'')+
    (d.recommended?'<span class="resource-badge rec">推荐</span>':'')+
    (d.kind==="link"?'<span class="resource-badge link">直达链接</span>':'')+
    '<span class="resource-badge">'+E(d.category||"其他资料")+'</span>';

  const action=d.kind==="link"
    ? '<a class="btn" target="_blank" rel="noopener noreferrer" href="/go/'+encodeURIComponent(d.id)+'">立即使用</a>'
    : '<a class="btn" href="/download/'+encodeURIComponent(d.id)+'">下载资料</a>';

  const preview=canPreview(d)
    ? '<button class="preview-btn" onclick="openPreview(\\''+d.id+'\\',\\''+E(d.title).replace(/'/g,"&#39;")+'\\')">在线预览</button>'
    : '';

  return '<article class="resource-card">'+
    '<div class="resource-top"><div class="resource-icon">'+(d.kind==="link"?"LINK":E(d.type||"FILE"))+'</div><div class="resource-badges">'+badges+'</div></div>'+
    '<h3>'+E(d.title)+'</h3>'+
    '<div class="resource-desc">'+E(d.description||"暂无简介")+'</div>'+
    '<div class="resource-meta">'+
      '<span>版本 '+E(d.version||"V1.0")+'</span>'+
      '<span>更新 '+dt(d.updatedAt||d.createdAt)+'</span>'+
      '<span>'+(d.kind==="link"?"访问":"下载")+' '+Number(d.downloads||0)+' 次</span>'+
      '<span>'+(d.kind==="link"?"外部工具":sz(d.size))+'</span>'+
    '</div>'+
    '<div class="resource-actions">'+preview+action+'</div>'+
  '</article>';
}
function filtered(){
  const q=document.getElementById("q").value.toLowerCase().trim();
  const c=document.getElementById("cat").value;
  return docs.filter(d=>
    (!q||((String(d.title||"")+" "+String(d.description||"")+" "+String(d.category||"")+" "+String(d.version||"")).toLowerCase().includes(q))) &&
    (!c||d.category===c)
  );
}
function render(){
  const arr=filtered();
  document.getElementById("count").textContent="共 "+arr.length+" 项";
  document.getElementById("grid").innerHTML=arr.length?arr.map(card).join(""):'<div class="empty">没有找到符合条件的资料</div>';

  const rec=docs.filter(d=>d.recommended);
  const rs=document.getElementById("recommendedSection");
  if(rec.length){
    document.getElementById("recommendedGrid").innerHTML=rec.slice(0,6).map(card).join("");
    rs.classList.remove("hidden");
  }else{
    rs.classList.add("hidden");
  }
}
window.openPreview=(id,title)=>{
  document.getElementById("previewTitle").textContent=title||"在线预览";
  document.getElementById("previewFrame").src="/preview/"+encodeURIComponent(id);
  document.getElementById("previewMask").classList.remove("hidden");
};
function closePreview(){
  document.getElementById("previewMask").classList.add("hidden");
  document.getElementById("previewFrame").src="about:blank";
}
document.getElementById("previewClose").onclick=closePreview;
document.getElementById("previewMask").addEventListener("click",e=>{if(e.target.id==="previewMask")closePreview()});

fetch("/api/site-settings").then(r=>r.json()).then(s=>{
  const a=s.announcement||{};
  const ab=document.getElementById("announcementBox");
  if(a.enabled && (a.title||a.content)){
    document.getElementById("announcementTitle").textContent=a.title||"置顶公告";
    document.getElementById("announcementContent").textContent=a.content||"";
    ab.classList.remove("hidden");
  }

  const sub=s.submission||{};
  const sb=document.getElementById("submissionBox");
  if(sub.enabled && (sub.email||sub.content)){
    document.getElementById("submissionTitle").textContent=sub.title||"投稿邮箱";
    document.getElementById("submissionContent").textContent=sub.content||"";
    const email=document.getElementById("submissionEmail");
    if(sub.email){
      email.textContent=sub.email;
      email.href="mailto:"+encodeURIComponent(sub.email);
    }else{
      email.textContent="邮箱暂未设置";
      email.removeAttribute("href");
    }
    sb.classList.remove("hidden");
  }
}).catch(()=>{});

fetch("/api/documents").then(r=>r.json()).then(x=>{
  docs=x;
  document.getElementById("heroCount").textContent=docs.length+" 项资源";
  const fileCount=docs.filter(d=>d.kind!=="link").length;
  const linkCount=docs.filter(d=>d.kind==="link").length;
  document.getElementById("heroSub").textContent="文件 "+fileCount+" 项 · 工具链接 "+linkCount+" 项 · 持续更新";
  const cs=[...new Set(docs.map(d=>d.category).filter(Boolean))];
  document.getElementById("cat").innerHTML='<option value="">全部分类</option>'+cs.map(c=>'<option>'+E(c)+'</option>').join("");
  render();
});
document.getElementById("q").oninput=render;
document.getElementById("cat").onchange=render;
</script>
</body>
</html>`;

const internalResourceHtml = `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>人民邮电出版社｜内部资料中心</title>
<style>${css}</style>
</head>
<body>

<div id="internalLogin" class="internal-login-wrap">
  <section class="internal-login-card">
    <div class="internal-brand"><span class="internal-mark">邮</span>人民邮电出版社</div>
    <h1>内部资料中心</h1>
    <p>本页面仅供内部人员访问。请输入内部访问密码后进入。</p>
    <form id="internalLoginForm">
      <input id="internalPassword" type="password" placeholder="内部访问密码" required>
      <button class="btn" style="width:100%;margin-top:12px">进入内部资料中心</button>
      <div id="internalLoginMsg"></div>
    </form>
  </section>
</div>

<div id="internalLibrary" class="internal-page hidden">
  <div class="internal-shell">
    <nav class="internal-nav">
      <div class="internal-brand"><span class="internal-mark">邮</span>内部资料中心</div>
      <button id="internalLogout" class="mini">退出内部中心</button>
    </nav>

    <header class="internal-hero">
      <div class="tag" style="background:rgba(255,255,255,.1);border-color:rgba(255,255,255,.18);color:#fff">仅限内部访问</div>
      <h1>人民邮电出版社｜内部资料中心</h1>
      <p>内部视频、培训资料、图片、文档、素材包等统一管理。可在线播放、在线查看或直接下载。</p>
    </header>

    <div class="internal-toolbar">
      <input id="internalSearch" placeholder="搜索标题、分类或简介">
      <select id="internalCategory"><option value="">全部分类</option></select>
    </div>

    <main id="internalGrid" class="internal-grid"></main>
  </div>
</div>

<div id="internalViewMask" class="internal-view-mask hidden">
  <div class="internal-view-dialog">
    <div class="internal-view-head">
      <strong id="internalViewTitle">在线查看</strong>
      <button id="internalViewClose" class="close-btn" type="button">×</button>
    </div>
    <div id="internalViewBody"></div>
  </div>
</div>

<script>
const IE=s=>String(s||"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#039;"}[c]));
let internalItems=[];

function isPreviewable(item){
  return ["video","audio","image","pdf","text"].includes(item.resourceKind);
}
function humanSize(b=0){
  if(!b)return "—";
  const u=["B","KB","MB","GB","TB"]; let i=0,n=Number(b);
  while(n>=1024&&i<u.length-1){n/=1024;i++}
  return (i===0?Math.round(n):n.toFixed(n>=10?1:2))+" "+u[i];
}
function shortDate(v){
  const d=new Date(v||"");
  if(Number.isNaN(d.getTime())) return "—";
  return d.getFullYear()+"-"+String(d.getMonth()+1).padStart(2,"0")+"-"+String(d.getDate()).padStart(2,"0");
}
async function internalAuthState(){
  try{
    const r=await fetch("/api/internal-access/me");
    const d=await r.json();
    document.getElementById("internalLogin").classList.toggle("hidden",d.authorized);
    document.getElementById("internalLibrary").classList.toggle("hidden",!d.authorized);
    if(d.authorized) loadInternalItems();
  }catch{}
}

document.getElementById("internalLoginForm").onsubmit=async e=>{
  e.preventDefault();
  const m=document.getElementById("internalLoginMsg");
  m.className="notice";
  m.textContent="正在验证...";
  try{
    const r=await fetch("/api/internal-access/login",{
      method:"POST",
      headers:{"Content-Type":"application/json"},
      body:JSON.stringify({password:document.getElementById("internalPassword").value})
    });
    const d=await r.json().catch(()=>({}));
    if(r.ok){
      m.className="ok";
      m.textContent="验证成功";
      document.getElementById("internalPassword").value="";
      internalAuthState();
    }else{
      m.className="err";
      m.textContent=d.error||"密码错误";
    }
  }catch{
    m.className="err";
    m.textContent="验证请求失败，请稍后重试";
  }
};

document.getElementById("internalLogout").onclick=async()=>{
  await fetch("/api/internal-access/logout",{method:"POST"});
  closeInternalView();
  internalAuthState();
};

function internalCard(item){
  const preview=isPreviewable(item)
    ? '<button class="mini primary" onclick="event.stopPropagation();openInternalView(\\''+item.id+'\\',\\''+IE(item.title).replace(/'/g,"&#39;")+'\\',\\''+item.resourceKind+'\\')">'+(item.resourceKind==="video"?"播放":"在线查看")+'</button>'
    : '';
  const cover=item.hasCover
    ? '<img class="internal-cover-img" src="/internal-resource/cover/'+encodeURIComponent(item.id)+'" alt="" loading="lazy"><span class="internal-cover-shade"></span>'
    : '';

  return '<article class="internal-card">'+
    '<div class="internal-cover">'+
      cover+
      '<span class="internal-type">'+IE(item.category||"内部资料")+'</span>'+
      (item.pinned?'<span class="internal-pin">置顶</span>':'')+
      (!item.hasCover?'<span class="internal-file-icon">'+IE(item.type||"FILE")+'</span>':'')+
    '</div>'+
    '<div class="internal-card-body">'+
      '<h3>'+IE(item.title||"未命名资料")+'</h3>'+
      '<p>'+IE(item.description||"暂无简介")+'</p>'+
      '<div class="internal-meta"><span>'+humanSize(item.size)+'</span><span>'+shortDate(item.updatedAt||item.createdAt)+'</span></div>'+
      '<div class="internal-actions">'+
        preview+
        '<a class="mini" href="/internal-resource/download/'+encodeURIComponent(item.id)+'" onclick="event.stopPropagation()">下载</a>'+
      '</div>'+
    '</div>'+
  '</article>';
}

function renderInternalItems(){
  const q=document.getElementById("internalSearch").value.toLowerCase().trim();
  const c=document.getElementById("internalCategory").value;
  const arr=internalItems.filter(v=>
    (!q||(String(v.title||"")+" "+String(v.description||"")+" "+String(v.category||"")+" "+String(v.type||"")).toLowerCase().includes(q)) &&
    (!c||v.category===c)
  );
  document.getElementById("internalGrid").innerHTML=arr.length
    ? arr.map(internalCard).join("")
    : '<div class="internal-empty">暂时没有符合条件的内部资料</div>';
}

async function loadInternalItems(){
  const r=await fetch("/api/internal-resources");
  if(r.status===401) return internalAuthState();
  internalItems=await r.json();
  const cats=[...new Set(internalItems.map(v=>v.category).filter(Boolean))];
  document.getElementById("internalCategory").innerHTML='<option value="">全部分类</option>'+cats.map(c=>'<option>'+IE(c)+'</option>').join("");
  renderInternalItems();
}

window.openInternalView=(id,title,kind)=>{
  const body=document.getElementById("internalViewBody");
  const url="/internal-resource/open/"+encodeURIComponent(id);
  document.getElementById("internalViewTitle").textContent=title||"在线查看";

  if(kind==="video"){
    body.innerHTML='<video class="internal-video" controls playsinline autoplay src="'+url+'"></video>';
  }else if(kind==="audio"){
    body.innerHTML='<audio class="internal-audio" controls autoplay src="'+url+'"></audio>';
  }else if(kind==="image"){
    body.innerHTML='<img class="internal-image" src="'+url+'" alt="">';
  }else{
    body.innerHTML='<iframe class="internal-frame" src="'+url+'" title="在线预览"></iframe>';
  }
  document.getElementById("internalViewMask").classList.remove("hidden");
};

function closeInternalView(){
  document.getElementById("internalViewMask").classList.add("hidden");
  document.getElementById("internalViewBody").innerHTML="";
}
document.getElementById("internalViewClose").onclick=closeInternalView;
document.getElementById("internalViewMask").addEventListener("click",e=>{if(e.target.id==="internalViewMask")closeInternalView()});
document.getElementById("internalSearch").oninput=renderInternalItems;
document.getElementById("internalCategory").onchange=renderInternalItems;

internalAuthState();
</script>
</body>
</html>`;

const adminHtml = `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>人民邮电出版社工具包｜资料管理后台</title>
<style>${css}</style>
</head>
<body>

<div class="admin">
  <section id="login" class="panel login">
    <div class="brand"><span class="logo">AI</span>人民邮电出版社工具包后台</div>
    <h1>管理员登录</h1>
    <p class="notice">登录后可以上传、编辑、隐藏或删除资料。</p>
    <form id="lf">
      <input id="pw" type="password" placeholder="管理员密码" required>
      <button class="btn" style="width:100%;margin-top:12px">登录后台</button>
      <div id="lm"></div>
    </form>
  </section>

  <div id="main" class="hidden">
    <div class="row" style="margin-bottom:18px">
      <div>
        <h1 style="margin:0">资料管理</h1>
        <p class="notice">文件和直达链接发布后都会自动出现在前台；名称、分类、简介和链接地址都可以随时修改。</p>
      </div>
      <div class="actions">
        <a class="mini" href="/" target="_blank">查看前台</a>
        <button id="lo" class="mini">退出</button>
      </div>
    </div>

    <section class="panel">
      <div class="row" style="align-items:flex-start">
        <div>
          <h2 style="margin:0 0 5px">页面信息设置</h2>
          <div class="notice">这里可以随时修改前台的置顶公告和投稿邮箱，不需要改代码。</div>
        </div>
      </div>

      <div class="settings-grid" style="margin-top:18px">
        <form id="announcementForm" class="settings-card">
          <div class="switch-row">
            <strong>置顶公告</strong>
            <label style="margin:0;display:flex;align-items:center;gap:7px">
              <input id="announcementEnabled" type="checkbox">
              <span>前台显示</span>
            </label>
          </div>

          <div style="margin-bottom:12px">
            <label>公告标题</label>
            <input id="announcementTitleInput" placeholder="例如：重要通知">
          </div>

          <div style="margin-bottom:12px">
            <label>公告内容</label>
            <textarea id="announcementContentInput" placeholder="填写需要长期置顶展示的公告内容"></textarea>
          </div>

          <button class="btn" type="submit">保存公告</button>
          <span id="announcementMsg"></span>
        </form>

        <form id="submissionForm" class="settings-card">
          <div class="switch-row">
            <strong>投稿邮箱</strong>
            <label style="margin:0;display:flex;align-items:center;gap:7px">
              <input id="submissionEnabled" type="checkbox">
              <span>前台显示</span>
            </label>
          </div>

          <div style="margin-bottom:12px">
            <label>板块标题</label>
            <input id="submissionTitleInput" placeholder="投稿邮箱">
          </div>

          <div style="margin-bottom:12px">
            <label>投稿邮箱地址</label>
            <input id="submissionEmailInput" type="email" placeholder="example@email.com">
          </div>

          <div style="margin-bottom:12px">
            <label>投稿说明</label>
            <textarea id="submissionContentInput" placeholder="例如：投稿请注明作品名称、作者姓名及联系方式。"></textarea>
          </div>

          <button class="btn" type="submit">保存投稿信息</button>
          <span id="submissionMsg"></span>
        </form>
      </div>
    </section>

    <section class="panel">
      <h2>上传新资料</h2>
      <form id="uf" class="form">
        <div>
          <label>文档名称</label>
          <input name="title" required>
        </div>
        <div>
          <label>分类</label>
          <input name="category" required>
        </div>
        <div>
          <label>版本</label>
          <input name="version" value="V1.0" placeholder="例如：V1.0">
        </div>
        <div>
          <label>排序值</label>
          <input name="sortOrder" type="number" value="0" placeholder="数字越大越靠前">
        </div>
        <div class="full">
          <label>简介</label>
          <textarea name="description" placeholder="填写这份资料的介绍"></textarea>
        </div>
        <div class="full">
          <label>选择文件</label>
          <input name="file" type="file" required>
          <p class="notice">支持 PDF、Word、PPT、Excel、ZIP/RAR/7Z、TXT，单文件最大 ${MAX_UPLOAD_MB}MB。大文件直接上传到 Bucket，不经过网站服务器。</p>
        </div>
        <div class="full">
          <button class="btn">上传并发布</button>
          <span id="um"></span>
        </div>
      </form>
    </section>

    <section class="panel">
      <div class="row" style="align-items:flex-start">
        <div>
          <h2 style="margin:0 0 5px">添加直达链接</h2>
          <div class="notice">适合放生视频、生图、工具平台、教程页等网址。访客点击后直接跳转。</div>
        </div>
        <span class="badge" style="background:#eef4ff;color:#3538cd">LINK</span>
      </div>

      <form id="linkForm" class="form" style="margin-top:18px">
        <div>
          <label>链接名称</label>
          <input name="title" placeholder="例如：AI生视频工具" required>
        </div>
        <div>
          <label>分类</label>
          <input name="category" placeholder="例如：生视频工具" required>
        </div>
        <div>
          <label>版本</label>
          <input name="version" value="V1.0" placeholder="例如：V1.0">
        </div>
        <div>
          <label>排序值</label>
          <input name="sortOrder" type="number" value="0" placeholder="数字越大越靠前">
        </div>
        <div class="full">
          <label>简介</label>
          <textarea name="description" placeholder="例如：点击进入在线AI视频生成平台"></textarea>
        </div>
        <div class="full">
          <label>直达网址</label>
          <input name="url" type="url" placeholder="https://..." required>
          <p class="notice">请填写完整网址，必须以 http:// 或 https:// 开头。</p>
        </div>
        <div class="full">
          <button class="btn" type="submit">发布直达链接</button>
          <span id="linkMsg"></span>
        </div>
      </form>
    </section>

    <section class="panel">
      <div class="internal-admin-head">
        <div>
          <h2 style="margin:0 0 5px">内部资料管理</h2>
          <div class="notice">仅供内部密码页面使用，不会显示在公开首页。支持视频、图片、文档、压缩包、音频及其他文件。</div>
        </div>
        <div style="display:flex;gap:8px;flex-wrap:wrap">
          <button id="backfillCoversBtn" class="mini" type="button">一键补齐视频封面</button>
          <a class="mini primary" href="/internal" target="_blank">打开内部资料中心</a>
        </div>
      </div>

      <form id="internalUploadForm" class="form" style="margin-top:18px">
        <div>
          <label>资料名称</label>
          <input name="title" placeholder="例如：内部培训视频 / 素材包 / 项目文档" required>
        </div>
        <div>
          <label>分类</label>
          <input name="category" placeholder="例如：内部培训 / 视频 / 项目资料" required>
        </div>
        <div>
          <label>排序值</label>
          <input name="sortOrder" type="number" value="0" placeholder="数字越大越靠前">
        </div>
        <div>
          <label>选择文件</label>
          <input name="file" type="file" required>
        </div>
        <div class="full">
          <label>简介</label>
          <textarea name="description" placeholder="填写这份内部资料的简介"></textarea>
        </div>
        <div class="full">
          <p class="notice">内部资料不使用公开资料区的 2GB 上限，也不限制文件扩展名。大文件会自动分片上传到 Railway Bucket。上传视频时会自动截取约 0.3 秒处的画面作为封面。</p>
          <div id="internalCoverPreviewWrap" class="hidden" style="margin:10px 0 8px">
            <div class="notice" style="margin-bottom:6px">自动封面预览</div>
            <img id="internalCoverPreview" alt="" style="width:240px;max-width:100%;aspect-ratio:16/9;object-fit:cover;border-radius:12px;border:1px solid #e4e7ec">
          </div>
          <button class="btn" type="submit">上传内部资料</button>
          <span id="internalUploadMsg"></span>
          <div id="internalProgressWrap" class="internal-progress hidden"><span id="internalProgressBar"></span></div>
        </div>
      </form>

      <div class="row" style="margin-top:24px">
        <div>
          <strong>已添加内部资料</strong>
          <div class="notice">可置顶、修改名称/分类/简介/排序、隐藏或删除。</div>
        </div>
        <span id="internalAdminCount" class="notice"></span>
      </div>
      <div id="internalAdminList" class="internal-admin-list"></div>
    </section>

    <section class="panel">
      <div class="row">
        <div>
          <h2 style="margin-bottom:4px">已上传资料</h2>
          <div class="notice">点击“编辑资料”即可修改简介，不会重新上传文件。</div>
        </div>
        <span id="ct" class="notice"></span>
      </div>
      <div id="list"></div>
    </section>
  </div>
</div>

<div id="editMask" class="modal-mask hidden">
  <div class="modal">
    <div class="modal-head">
      <h2>编辑资料</h2>
      <button id="editClose" class="close-btn" type="button">×</button>
    </div>

    <form id="editForm">
      <input type="hidden" id="editId">

      <div style="margin-bottom:14px">
        <label>文档名称</label>
        <input id="editTitle" required>
      </div>

      <div style="margin-bottom:14px">
        <label>分类</label>
        <input id="editCategory" required>
      </div>

      <div style="margin-bottom:14px">
        <label>简介</label>
        <textarea id="editDescription" placeholder="修改这份资料的简介"></textarea>
      </div>

      <div class="edit-two" style="margin-bottom:14px">
        <div>
          <label>版本</label>
          <input id="editVersion" placeholder="例如：V1.0">
        </div>
        <div>
          <label>排序值</label>
          <input id="editSortOrder" type="number" placeholder="数字越大越靠前">
        </div>
      </div>

      <div style="margin-bottom:14px">
        <label>最后更新时间</label>
        <div id="editUpdatedAt" class="file-lock">保存修改后自动更新</div>
      </div>

      <div id="editFileBlock" style="margin-bottom:14px">
        <label>当前文件</label>
        <div id="editFileName" class="file-lock"></div>
        <div class="notice" style="margin-top:7px">这里只修改资料信息，原文件保持不变，不需要重新上传。</div>
      </div>

      <div id="editLinkBlock" class="hidden" style="margin-bottom:14px">
        <label>直达网址</label>
        <input id="editUrl" type="url" placeholder="https://...">
        <div class="notice" style="margin-top:7px">可以直接修改网址，不需要重新发布这条资料。</div>
      </div>

      <div id="editMsg"></div>

      <div class="modal-actions">
        <button id="editCancel" class="secondary" type="button">取消</button>
        <button class="btn" type="submit">保存修改</button>
      </div>
    </form>
  </div>
</div>

<script>
const E=s=>String(s||"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#039;"}[c]));
let adminDocs=[];
function formatAdminDate(v){
  if(!v)return "—";
  const d=new Date(v);
  if(Number.isNaN(d.getTime()))return "—";
  return d.getFullYear()+"-"+String(d.getMonth()+1).padStart(2,"0")+"-"+String(d.getDate()).padStart(2,"0")+" "+String(d.getHours()).padStart(2,"0")+":"+String(d.getMinutes()).padStart(2,"0");
}

async function auth(){
  const d=await fetch("/api/me").then(r=>r.json());
  document.getElementById("login").classList.toggle("hidden",d.isAdmin);
  document.getElementById("main").classList.toggle("hidden",!d.isAdmin);
  if(d.isAdmin){
    load();
    loadSiteSettings();
    loadAdminInternalResources();
  }
}

document.getElementById("lf").onsubmit=async e=>{
  e.preventDefault();
  const m=document.getElementById("lm");
  m.className="notice";
  m.textContent="正在登录...";
  try{
    const r=await fetch("/api/login",{
      method:"POST",
      headers:{"Content-Type":"application/json"},
      body:JSON.stringify({password:document.getElementById("pw").value})
    });
    const d=await r.json();
    if(r.ok){
      m.className="ok";
      m.textContent="登录成功";
      await auth();
    }else{
      m.className="err";
      m.textContent=d.error||"登录失败";
    }
  }catch{
    m.className="err";
    m.textContent="登录请求失败，请刷新页面后重试";
  }
};

document.getElementById("lo").onclick=async()=>{
  await fetch("/api/logout",{method:"POST"});
  auth();
};

document.getElementById("uf").onsubmit=async e=>{
  e.preventDefault();

  const m=document.getElementById("um");
  const form=e.target;
  const fd=new FormData(form);
  const file=fd.get("file");

  if(!file || !file.name){
    m.className="err";
    m.textContent=" 请选择文件";
    return;
  }

  m.className="notice";
  m.textContent=" 正在准备上传...";

  try{
    const prep=await fetch("/api/admin/uploads/presign",{
      method:"POST",
      headers:{"Content-Type":"application/json"},
      body:JSON.stringify({
        filename:file.name,
        size:file.size,
        contentType:file.type||"application/octet-stream"
      })
    });

    const p=await prep.json().catch(()=>({}));
    if(!prep.ok){
      m.className="err";
      m.textContent=" "+(p.error||"无法准备上传");
      return;
    }

    m.className="notice";
    m.textContent=" 正在上传 0%";

    await new Promise((resolve,reject)=>{
      const xhr=new XMLHttpRequest();
      xhr.open("PUT",p.uploadUrl,true);
      if(file.type) xhr.setRequestHeader("Content-Type",file.type);

      xhr.upload.onprogress=ev=>{
        if(ev.lengthComputable){
          const pct=Math.max(0,Math.min(100,Math.round(ev.loaded/ev.total*100)));
          m.textContent=" 正在上传 "+pct+"%";
        }
      };

      xhr.onload=()=>{
        if(xhr.status>=200 && xhr.status<300) resolve();
        else reject(new Error("Bucket 上传失败，HTTP "+xhr.status));
      };
      xhr.onerror=()=>reject(new Error("网络上传失败"));
      xhr.send(file);
    });

    m.textContent=" 正在保存资料信息...";

    const done=await fetch("/api/admin/uploads/complete",{
      method:"POST",
      headers:{"Content-Type":"application/json"},
      body:JSON.stringify({
        key:p.key,
        title:fd.get("title"),
        category:fd.get("category"),
        description:fd.get("description"),
        version:fd.get("version"),
        sortOrder:Number(fd.get("sortOrder")||0),
        originalName:file.name,
        type:(file.name.split(".").pop()||"FILE").toUpperCase(),
        size:file.size
      })
    });

    const d=await done.json().catch(()=>({}));
    if(done.ok){
      m.className="ok";
      m.textContent=" 上传成功";
      form.reset();
      load();
    }else{
      m.className="err";
      m.textContent=" "+(d.error||"保存失败");
    }
  }catch(err){
    m.className="err";
    m.textContent=" "+(err?.message||"上传失败");
  }
};



async function loadSiteSettings(){
  try{
    const r=await fetch("/api/admin/site-settings");
    if(r.status===401) return auth();
    const s=await r.json();

    const a=s.announcement||{};
    document.getElementById("announcementEnabled").checked=Boolean(a.enabled);
    document.getElementById("announcementTitleInput").value=a.title||"置顶公告";
    document.getElementById("announcementContentInput").value=a.content||"";

    const sub=s.submission||{};
    document.getElementById("submissionEnabled").checked=Boolean(sub.enabled);
    document.getElementById("submissionTitleInput").value=sub.title||"投稿邮箱";
    document.getElementById("submissionEmailInput").value=sub.email||"";
    document.getElementById("submissionContentInput").value=sub.content||"";
  }catch{}
}


let adminInternalResources=[];

function adminHumanSize(b=0){
  if(!b)return "—";
  const u=["B","KB","MB","GB","TB"]; let i=0,n=Number(b);
  while(n>=1024&&i<u.length-1){n/=1024;i++}
  return (i===0?Math.round(n):n.toFixed(n>=10?1:2))+" "+u[i];
}

async function loadAdminInternalResources(){
  try{
    const r=await fetch("/api/admin/internal-resources");
    if(r.status===401) return auth();
    adminInternalResources=await r.json();
    document.getElementById("internalAdminCount").textContent="共 "+adminInternalResources.length+" 项";
    document.getElementById("internalAdminList").innerHTML=adminInternalResources.length
      ? adminInternalResources.map(v=>
        '<div class="internal-admin-item">'+
          '<div>'+
            '<h3>'+E(v.title)+(v.pinned?' <span class="badge" style="background:#fff3cd;color:#8a6116">已置顶</span>':'')+(v.visible===false?' <span class="badge">已隐藏</span>':'')+'</h3>'+
            '<p>'+E(v.category||"内部资料")+' · '+E(v.type||"FILE")+' · '+adminHumanSize(v.size)+' · 访问 '+Number(v.accesses||0)+' 次 · 排序 '+Number(v.sortOrder||0)+'</p>'+
            '<div class="admin-desc">'+E(v.description||"暂无简介")+'</div>'+
          '</div>'+
          '<div class="actions">'+
            '<button class="mini" onclick="pinInternalResource(\\''+v.id+'\\','+Boolean(v.pinned)+')">'+(v.pinned?'取消置顶':'置顶')+'</button>'+
            ((v.resourceKind||"")==="video"?'<button class="mini" onclick="'+(v.coverObjectKey?'replaceInternalCover':'generateInternalCover')+'(\\''+v.id+'\\')">'+(v.coverObjectKey?'更换封面':'生成封面')+'</button>':'')+
            '<button class="mini primary" onclick="editInternalResource(\\''+v.id+'\\')">编辑</button>'+
            '<button class="mini" onclick="toggleInternalResource(\\''+v.id+'\\','+(v.visible!==false)+')">'+(v.visible===false?'显示':'隐藏')+'</button>'+
            '<button class="mini danger" onclick="deleteInternalResource(\\''+v.id+'\\')">删除</button>'+
          '</div>'+
        '</div>'
      ).join("")
      : '<p class="notice">还没有上传内部资料。</p>';
  }catch{}
}

function isVideoFile(file){
  const mime=String(file?.type||"").toLowerCase();
  const ext=String(file?.name||"").toLowerCase().split(".").pop();
  return mime.startsWith("video/") || ["mp4","webm","mov","m4v","mkv"].includes(ext);
}

async function extractVideoCover(file){
  if(!isVideoFile(file)) return null;

  const objectUrl=URL.createObjectURL(file);
  const video=document.createElement("video");
  video.preload="metadata";
  video.muted=true;
  video.playsInline=true;
  video.src=objectUrl;

  try{
    await new Promise((resolve,reject)=>{
      const timer=setTimeout(()=>reject(new Error("读取视频超时")),15000);
      video.onloadedmetadata=()=>{
        clearTimeout(timer);
        resolve();
      };
      video.onerror=()=>{
        clearTimeout(timer);
        reject(new Error("浏览器无法读取该视频格式"));
      };
    });

    const duration=Number(video.duration||0);
    let target=0.3;
    if(duration>0){
      target=Math.min(0.3,Math.max(0,duration-0.05));
    }

    await new Promise((resolve,reject)=>{
      const timer=setTimeout(()=>reject(new Error("视频取帧超时")),15000);
      video.onseeked=()=>{
        clearTimeout(timer);
        resolve();
      };
      video.onerror=()=>{
        clearTimeout(timer);
        reject(new Error("视频取帧失败"));
      };
      try{
        video.currentTime=target;
      }catch(err){
        clearTimeout(timer);
        reject(err);
      }
    });

    const sourceW=video.videoWidth||1280;
    const sourceH=video.videoHeight||720;
    const maxW=1280;
    const scale=Math.min(1,maxW/sourceW);
    const canvas=document.createElement("canvas");
    canvas.width=Math.max(1,Math.round(sourceW*scale));
    canvas.height=Math.max(1,Math.round(sourceH*scale));
    const ctx=canvas.getContext("2d");
    ctx.drawImage(video,0,0,canvas.width,canvas.height);

    const blob=await new Promise(resolve=>canvas.toBlob(resolve,"image/jpeg",0.84));
    if(!blob) throw new Error("封面生成失败");

    const preview=document.getElementById("internalCoverPreview");
    const wrap=document.getElementById("internalCoverPreviewWrap");
    if(preview&&wrap){
      preview.src=URL.createObjectURL(blob);
      wrap.classList.remove("hidden");
    }
    return blob;
  } finally {
    URL.revokeObjectURL(objectUrl);
  }
}

async function uploadInternalCoverBlob(blob,baseName){
  const prep=await fetch("/api/admin/internal-resources/cover-presign",{
    method:"POST",
    headers:{"Content-Type":"application/json"},
    body:JSON.stringify({
      filename:(baseName||"cover")+".jpg",
      size:blob.size,
      contentType:"image/jpeg"
    })
  });
  const data=await prep.json().catch(()=>({}));
  if(!prep.ok) throw new Error(data.error||"无法准备封面上传");
  await xhrPut(data.uploadUrl,blob,"image/jpeg");
  return data.key;
}

function xhrPut(url,blob,contentType,onProgress){
  return new Promise((resolve,reject)=>{
    const xhr=new XMLHttpRequest();
    xhr.open("PUT",url,true);
    if(contentType) xhr.setRequestHeader("Content-Type",contentType);
    xhr.upload.onprogress=e=>{ if(e.lengthComputable&&onProgress) onProgress(e.loaded,e.total); };
    xhr.onload=()=>{
      if(xhr.status>=200&&xhr.status<300){
        resolve(xhr.getResponseHeader("ETag"));
      }else{
        reject(new Error("Bucket 上传失败，HTTP "+xhr.status));
      }
    };
    xhr.onerror=()=>reject(new Error("网络上传失败"));
    xhr.send(blob);
  });
}

document.getElementById("internalUploadForm").onsubmit=async e=>{
  e.preventDefault();

  const form=e.target;
  const fd=new FormData(form);
  const file=fd.get("file");
  const msg=document.getElementById("internalUploadMsg");
  const wrap=document.getElementById("internalProgressWrap");
  const bar=document.getElementById("internalProgressBar");

  if(!file||!file.name){
    msg.className="err";
    msg.textContent=" 请选择文件";
    return;
  }

  let uploadState=null;
  let coverObjectKey="";
  wrap.classList.remove("hidden");
  bar.style.width="0%";
  msg.className="notice";
  msg.textContent=" 正在准备上传...";

  try{
    if(isVideoFile(file)){
      msg.textContent=" 正在提取视频封面...";
      try{
        const coverBlob=await extractVideoCover(file);
        if(coverBlob){
          msg.textContent=" 正在上传视频封面...";
          coverObjectKey=await uploadInternalCoverBlob(
            coverBlob,
            String(file.name||"video").replace(/\.[^.]+$/,"")
          );
        }
      }catch(coverErr){
        console.warn("自动封面生成失败，视频仍会继续上传：",coverErr);
        msg.textContent=" 自动封面生成失败，继续上传视频...";
      }
    }

    const init=await fetch("/api/admin/internal-resources/upload-init",{
      method:"POST",
      headers:{"Content-Type":"application/json"},
      body:JSON.stringify({
        filename:file.name,
        size:file.size,
        contentType:file.type||"application/octet-stream"
      })
    });
    uploadState=await init.json().catch(()=>({}));
    if(!init.ok) throw new Error(uploadState.error||"无法准备上传");

    if(uploadState.mode==="single"){
      await xhrPut(
        uploadState.uploadUrl,
        file,
        file.type||"application/octet-stream",
        loaded=>{
          const pct=Math.max(0,Math.min(100,Math.round(loaded/file.size*100)));
          bar.style.width=pct+"%";
          msg.textContent=" 正在上传 "+pct+"%";
        }
      );
    }else{
      const partSize=Number(uploadState.partSize);
      const partCount=Math.ceil(file.size/partSize);
      const partProgress=new Array(partCount).fill(0);
      const completedParts=new Array(partCount);
      let nextIndex=0;

      function updateProgress(){
        const loaded=partProgress.reduce((a,b)=>a+b,0);
        const pct=Math.max(0,Math.min(100,Math.round(loaded/file.size*100)));
        bar.style.width=pct+"%";
        msg.textContent=" 正在分片上传 "+pct+"%（"+completedParts.filter(Boolean).length+"/"+partCount+"）";
      }

      async function worker(){
        while(true){
          const index=nextIndex++;
          if(index>=partCount) return;

          const partNumber=index+1;
          const start=index*partSize;
          const end=Math.min(file.size,start+partSize);
          const blob=file.slice(start,end);

          const pr=await fetch("/api/admin/internal-resources/upload-part",{
            method:"POST",
            headers:{"Content-Type":"application/json"},
            body:JSON.stringify({
              key:uploadState.key,
              uploadId:uploadState.uploadId,
              partNumber
            })
          });
          const pd=await pr.json().catch(()=>({}));
          if(!pr.ok) throw new Error(pd.error||("无法准备第 "+partNumber+" 个分片"));

          const etag=await xhrPut(pd.uploadUrl,blob,"",(loaded)=>{
            partProgress[index]=loaded;
            updateProgress();
          });
          if(!etag) throw new Error("第 "+partNumber+" 个分片缺少 ETag");

          partProgress[index]=blob.size;
          completedParts[index]={PartNumber:partNumber,ETag:etag};
          updateProgress();
        }
      }

      const concurrency=Math.min(3,partCount);
      await Promise.all(Array.from({length:concurrency},()=>worker()));

      msg.textContent=" 正在合并分片...";
      const finishMultipart=await fetch("/api/admin/internal-resources/upload-complete-multipart",{
        method:"POST",
        headers:{"Content-Type":"application/json"},
        body:JSON.stringify({
          key:uploadState.key,
          uploadId:uploadState.uploadId,
          parts:completedParts
        })
      });
      const fm=await finishMultipart.json().catch(()=>({}));
      if(!finishMultipart.ok) throw new Error(fm.error||"合并分片失败");
    }

    msg.textContent=" 正在保存资料信息...";

    const done=await fetch("/api/admin/internal-resources/finalize",{
      method:"POST",
      headers:{"Content-Type":"application/json"},
      body:JSON.stringify({
        key:uploadState.key,
        title:fd.get("title"),
        category:fd.get("category"),
        description:fd.get("description"),
        sortOrder:Number(fd.get("sortOrder")||0),
        originalName:file.name,
        size:file.size,
        contentType:file.type||"application/octet-stream",
        coverObjectKey
      })
    });
    const d=await done.json().catch(()=>({}));
    if(!done.ok) throw new Error(d.error||"保存资料信息失败");

    bar.style.width="100%";
    msg.className="ok";
    msg.textContent=" 上传成功";
    form.reset();
    const coverWrap=document.getElementById("internalCoverPreviewWrap");
    const coverPreview=document.getElementById("internalCoverPreview");
    if(coverWrap) coverWrap.classList.add("hidden");
    if(coverPreview) coverPreview.removeAttribute("src");
    loadAdminInternalResources();
    setTimeout(()=>wrap.classList.add("hidden"),1000);
  }catch(err){
    if(coverObjectKey){
      fetch("/api/admin/internal-resources/cover-delete",{
        method:"POST",
        headers:{"Content-Type":"application/json"},
        body:JSON.stringify({coverObjectKey})
      }).catch(()=>{});
    }
    if(uploadState?.mode==="multipart" && uploadState?.key && uploadState?.uploadId){
      fetch("/api/admin/internal-resources/upload-abort",{
        method:"POST",
        headers:{"Content-Type":"application/json"},
        body:JSON.stringify({key:uploadState.key,uploadId:uploadState.uploadId})
      }).catch(()=>{});
    }
    msg.className="err";
    msg.textContent=" "+(err?.message||"上传失败");
  }
};

window.pinInternalResource=async(id,pinned)=>{
  await fetch("/api/admin/internal-resources/"+encodeURIComponent(id),{
    method:"PATCH",
    headers:{"Content-Type":"application/json"},
    body:JSON.stringify({pinned:!pinned})
  });
  loadAdminInternalResources();
};

window.toggleInternalResource=async(id,visible)=>{
  await fetch("/api/admin/internal-resources/"+encodeURIComponent(id),{
    method:"PATCH",
    headers:{"Content-Type":"application/json"},
    body:JSON.stringify({visible:!visible})
  });
  loadAdminInternalResources();
};

window.editInternalResource=async id=>{
  const v=adminInternalResources.find(x=>x.id===id);
  if(!v)return;

  const title=prompt("资料名称",v.title||"");
  if(title===null)return;
  const category=prompt("分类",v.category||"内部资料");
  if(category===null)return;
  const description=prompt("简介",v.description||"");
  if(description===null)return;
  const sortOrder=prompt("排序值（数字越大越靠前）",String(v.sortOrder||0));
  if(sortOrder===null)return;

  const r=await fetch("/api/admin/internal-resources/"+encodeURIComponent(id),{
    method:"PATCH",
    headers:{"Content-Type":"application/json"},
    body:JSON.stringify({title,category,description,sortOrder:Number(sortOrder||0)})
  });
  const d=await r.json().catch(()=>({}));
  if(!r.ok) alert(d.error||"修改失败");
  loadAdminInternalResources();
};

async function extractCoverFromVideoUrl(url){
  const video=document.createElement("video");
  video.preload="metadata";
  video.muted=true;
  video.playsInline=true;
  video.crossOrigin="anonymous";
  video.src=url;

  try{
    await new Promise((resolve,reject)=>{
      const timer=setTimeout(()=>reject(new Error("读取视频超时")),30000);
      video.onloadedmetadata=()=>{
        clearTimeout(timer);
        resolve();
      };
      video.onerror=()=>{
        clearTimeout(timer);
        reject(new Error("浏览器无法读取这个视频"));
      };
    });

    const duration=Number(video.duration||0);
    const target=duration>0 ? Math.min(0.3,Math.max(0,duration-0.05)) : 0;

    await new Promise((resolve,reject)=>{
      const timer=setTimeout(()=>reject(new Error("视频取帧超时")),30000);
      video.onseeked=()=>{
        clearTimeout(timer);
        resolve();
      };
      video.onerror=()=>{
        clearTimeout(timer);
        reject(new Error("视频取帧失败"));
      };
      try{
        video.currentTime=target;
      }catch(err){
        clearTimeout(timer);
        reject(err);
      }
    });

    const sourceW=video.videoWidth||1280;
    const sourceH=video.videoHeight||720;
    const maxW=1280;
    const scale=Math.min(1,maxW/sourceW);
    const canvas=document.createElement("canvas");
    canvas.width=Math.max(1,Math.round(sourceW*scale));
    canvas.height=Math.max(1,Math.round(sourceH*scale));
    const ctx=canvas.getContext("2d");
    ctx.drawImage(video,0,0,canvas.width,canvas.height);

    const blob=await new Promise(resolve=>canvas.toBlob(resolve,"image/jpeg",0.84));
    if(!blob) throw new Error("封面生成失败");
    return blob;
  } finally {
    video.pause();
    video.removeAttribute("src");
    video.load();
  }
}

async function createCoverForExistingItem(item,quiet=false){
  if(!item || (item.resourceKind||"")!=="video"){
    throw new Error("这不是视频资料");
  }

  const sourceResp=await fetch("/api/admin/internal-resources/"+encodeURIComponent(item.id)+"/source-url");
  const sourceData=await sourceResp.json().catch(()=>({}));
  if(!sourceResp.ok) throw new Error(sourceData.error||"无法读取原视频");

  const blob=await extractCoverFromVideoUrl(sourceData.url);
  const newKey=await uploadInternalCoverBlob(blob,String(item.originalName||item.title||"video").replace(/\.[^.]+$/,""));

  const save=await fetch("/api/admin/internal-resources/"+encodeURIComponent(item.id)+"/cover",{
    method:"PATCH",
    headers:{"Content-Type":"application/json"},
    body:JSON.stringify({coverObjectKey:newKey})
  });
  const saved=await save.json().catch(()=>({}));
  if(!save.ok){
    fetch("/api/admin/internal-resources/cover-delete",{
      method:"POST",
      headers:{"Content-Type":"application/json"},
      body:JSON.stringify({coverObjectKey:newKey})
    }).catch(()=>{});
    throw new Error(saved.error||"保存封面失败");
  }

  if(!quiet) alert("视频封面已自动生成");
}

window.generateInternalCover=async id=>{
  const item=adminInternalResources.find(x=>x.id===id);
  if(!item)return;
  try{
    await createCoverForExistingItem(item,false);
    loadAdminInternalResources();
  }catch(err){
    alert(err?.message||"自动生成封面失败");
  }
};

document.getElementById("backfillCoversBtn").onclick=async()=>{
  const btn=document.getElementById("backfillCoversBtn");
  const missing=adminInternalResources.filter(v=>(v.resourceKind||"")==="video"&&!v.coverObjectKey);

  if(!missing.length){
    alert("当前所有视频都已经有封面");
    return;
  }

  if(!confirm("检测到 "+missing.length+" 个视频缺少封面。将逐个从 Bucket 读取视频并自动截取约0.3秒画面，是否继续？")) return;

  btn.disabled=true;
  const oldText=btn.textContent;
  let success=0,failed=0;

  try{
    for(let i=0;i<missing.length;i++){
      btn.textContent="生成封面 "+(i+1)+"/"+missing.length;
      try{
        await createCoverForExistingItem(missing[i],true);
        success++;
      }catch(err){
        console.warn("封面生成失败：",missing[i].title,err);
        failed++;
      }
    }
  }finally{
    btn.disabled=false;
    btn.textContent=oldText;
    await loadAdminInternalResources();
  }

  alert("封面补齐完成：成功 "+success+" 个，失败 "+failed+" 个。");
};

window.replaceInternalCover=async id=>{
  const item=adminInternalResources.find(x=>x.id===id);
  if(!item)return;

  const input=document.createElement("input");
  input.type="file";
  input.accept="image/jpeg,image/png,image/webp,.jpg,.jpeg,.png,.webp";
  input.onchange=async()=>{
    const file=input.files&&input.files[0];
    if(!file)return;
    try{
      const prep=await fetch("/api/admin/internal-resources/cover-presign",{
        method:"POST",
        headers:{"Content-Type":"application/json"},
        body:JSON.stringify({
          filename:file.name,
          size:file.size,
          contentType:file.type||"image/jpeg"
        })
      });
      const pd=await prep.json().catch(()=>({}));
      if(!prep.ok) throw new Error(pd.error||"无法准备封面上传");

      await xhrPut(pd.uploadUrl,file,file.type||"image/jpeg");

      const r=await fetch("/api/admin/internal-resources/"+encodeURIComponent(id)+"/cover",{
        method:"PATCH",
        headers:{"Content-Type":"application/json"},
        body:JSON.stringify({coverObjectKey:pd.key})
      });
      const d=await r.json().catch(()=>({}));
      if(!r.ok) throw new Error(d.error||"保存封面失败");

      alert("封面已更新");
      loadAdminInternalResources();
    }catch(err){
      alert(err?.message||"更换封面失败");
    }
  };
  input.click();
};

window.deleteInternalResource=async id=>{
  if(!confirm("确定删除这份内部资料吗？Bucket 中的实体文件也会一起删除。"))return;
  const r=await fetch("/api/admin/internal-resources/"+encodeURIComponent(id),{method:"DELETE"});
  const d=await r.json().catch(()=>({}));
  if(!r.ok)alert(d.error||"删除失败");
  loadAdminInternalResources();
};


document.getElementById("announcementForm").onsubmit=async e=>{
  e.preventDefault();
  const m=document.getElementById("announcementMsg");
  m.className="notice";
  m.textContent=" 正在保存...";

  try{
    const r=await fetch("/api/admin/site-settings",{
      method:"PATCH",
      headers:{"Content-Type":"application/json"},
      body:JSON.stringify({
        announcement:{
          enabled:document.getElementById("announcementEnabled").checked,
          title:document.getElementById("announcementTitleInput").value,
          content:document.getElementById("announcementContentInput").value
        }
      })
    });
    const d=await r.json().catch(()=>({}));
    if(r.ok){
      m.className="ok";
      m.textContent=" 保存成功";
    }else{
      m.className="err";
      m.textContent=" "+(d.error||"保存失败");
    }
  }catch{
    m.className="err";
    m.textContent=" 保存请求失败";
  }
};

document.getElementById("submissionForm").onsubmit=async e=>{
  e.preventDefault();
  const m=document.getElementById("submissionMsg");
  m.className="notice";
  m.textContent=" 正在保存...";

  try{
    const r=await fetch("/api/admin/site-settings",{
      method:"PATCH",
      headers:{"Content-Type":"application/json"},
      body:JSON.stringify({
        submission:{
          enabled:document.getElementById("submissionEnabled").checked,
          title:document.getElementById("submissionTitleInput").value,
          email:document.getElementById("submissionEmailInput").value,
          content:document.getElementById("submissionContentInput").value
        }
      })
    });
    const d=await r.json().catch(()=>({}));
    if(r.ok){
      m.className="ok";
      m.textContent=" 保存成功";
    }else{
      m.className="err";
      m.textContent=" "+(d.error||"保存失败");
    }
  }catch{
    m.className="err";
    m.textContent=" 保存请求失败";
  }
};

document.getElementById("linkForm").onsubmit=async e=>{
  e.preventDefault();
  const m=document.getElementById("linkMsg");
  m.className="notice";
  m.textContent=" 正在发布...";

  const form=new FormData(e.target);
  const payload={
    title:form.get("title"),
    category:form.get("category"),
    description:form.get("description"),
    version:form.get("version"),
    sortOrder:Number(form.get("sortOrder")||0),
    url:form.get("url")
  };

  try{
    const r=await fetch("/api/admin/links",{
      method:"POST",
      headers:{"Content-Type":"application/json"},
      body:JSON.stringify(payload)
    });
    const d=await r.json().catch(()=>({}));

    if(r.ok){
      m.className="ok";
      m.textContent=" 发布成功";
      e.target.reset();
      load();
    }else{
      m.className="err";
      m.textContent=" "+(d.error||"发布失败");
    }
  }catch{
    m.className="err";
    m.textContent=" 发布请求失败";
  }
};

async function load(){
  const r=await fetch("/api/admin/documents");
  if(r.status===401) return auth();
  adminDocs=await r.json();
  document.getElementById("ct").textContent="共 "+adminDocs.length+" 份";

  document.getElementById("list").innerHTML=adminDocs.length
    ? adminDocs.map(d=>
      '<div class="item">'+
        '<div>'+
          '<h3>'+E(d.title)+(d.pinned?' <span class="badge" style="background:#fff3cd;color:#8a6116">已置顶</span>':'')+(d.recommended?' <span class="badge recommend-chip">已推荐</span>':'')+(d.visible===false?' <span class="badge">已隐藏</span>':'')+'</h3>'+
          '<p>'+E(d.category)+' · '+(d.kind==="link"?"直达链接":E(d.type||"FILE"))+' · '+(d.kind==="link"?"访问 ":"下载 ")+Number(d.downloads||0)+' 次</p>'+
          '<div class="admin-desc">'+E(d.description||"暂无简介")+'</div>'+
          '<div class="admin-meta-grid">'+
            '<div class="admin-meta-chip">版本：'+E(d.version||"V1.0")+'</div>'+
            '<div class="admin-meta-chip">排序：'+Number(d.sortOrder||0)+'</div>'+
            '<div class="admin-meta-chip">更新：'+formatAdminDate(d.updatedAt||d.createdAt)+'</div>'+
            '<div class="admin-meta-chip">'+(d.kind==="link"?"工具链接":"资料文件")+'</div>'+
          '</div>'+
        '</div>'+
        '<div class="actions">'+
          '<button class="mini" onclick="pinD(\\''+d.id+'\\','+Boolean(d.pinned)+')">'+(d.pinned?'取消置顶':'置顶')+'</button>'+
          '<button class="mini" onclick="recD(\\''+d.id+'\\','+Boolean(d.recommended)+')">'+(d.recommended?'取消推荐':'推荐')+'</button>'+
          '<button class="mini primary" onclick="openEdit(\\''+d.id+'\\')">编辑资料</button>'+
          '<button class="mini" onclick="visD(\\''+d.id+'\\','+(d.visible!==false)+')">'+(d.visible===false?'显示':'隐藏')+'</button>'+
          '<button class="mini danger" onclick="delD(\\''+d.id+'\\')">删除</button>'+
        '</div>'+
      '</div>'
    ).join("")
    : '<p class="notice">还没有上传资料。</p>';
}

window.openEdit=id=>{
  const d=adminDocs.find(x=>x.id===id);
  if(!d) return;

  document.getElementById("editId").value=d.id;
  document.getElementById("editTitle").value=d.title||"";
  document.getElementById("editCategory").value=d.category||"";
  document.getElementById("editDescription").value=d.description||"";
  document.getElementById("editVersion").value=d.version||"V1.0";
  document.getElementById("editSortOrder").value=Number(d.sortOrder||0);
  document.getElementById("editUpdatedAt").textContent=formatAdminDate(d.updatedAt||d.createdAt);

  const isLink=d.kind==="link";
  document.getElementById("editFileBlock").classList.toggle("hidden",isLink);
  document.getElementById("editLinkBlock").classList.toggle("hidden",!isLink);
  document.getElementById("editFileName").textContent=d.originalName||"原文件";
  document.getElementById("editUrl").value=isLink?(d.url||""):"";

  document.getElementById("editMsg").textContent="";
  document.getElementById("editMask").classList.remove("hidden");
};

function closeEdit(){
  document.getElementById("editMask").classList.add("hidden");
}
document.getElementById("editClose").onclick=closeEdit;
document.getElementById("editCancel").onclick=closeEdit;
document.getElementById("editMask").addEventListener("click",e=>{
  if(e.target.id==="editMask") closeEdit();
});

document.getElementById("editForm").onsubmit=async e=>{
  e.preventDefault();

  const id=document.getElementById("editId").value;
  const msg=document.getElementById("editMsg");
  msg.className="notice";
  msg.textContent="正在保存...";

  try{
    const r=await fetch("/api/admin/documents/"+encodeURIComponent(id),{
      method:"PATCH",
      headers:{"Content-Type":"application/json"},
      body:JSON.stringify({
        title:document.getElementById("editTitle").value,
        category:document.getElementById("editCategory").value,
        description:document.getElementById("editDescription").value,
        version:document.getElementById("editVersion").value,
        sortOrder:Number(document.getElementById("editSortOrder").value||0),
        url:document.getElementById("editLinkBlock").classList.contains("hidden")
          ? undefined
          : document.getElementById("editUrl").value
      })
    });

    const d=await r.json().catch(()=>({}));
    if(r.ok){
      msg.className="ok";
      msg.textContent="保存成功";
      await load();
      setTimeout(closeEdit,350);
    }else{
      msg.className="err";
      msg.textContent=d.error||"保存失败";
    }
  }catch{
    msg.className="err";
    msg.textContent="保存请求失败";
  }
};

window.pinD=async(id,pinned)=>{
  await fetch("/api/admin/documents/"+encodeURIComponent(id),{
    method:"PATCH",
    headers:{"Content-Type":"application/json"},
    body:JSON.stringify({pinned:!pinned})
  });
  load();
};

window.recD=async(id,recommended)=>{
  await fetch("/api/admin/documents/"+encodeURIComponent(id),{
    method:"PATCH",
    headers:{"Content-Type":"application/json"},
    body:JSON.stringify({recommended:!recommended})
  });
  load();
};

window.visD=async(id,v)=>{
  await fetch("/api/admin/documents/"+encodeURIComponent(id),{
    method:"PATCH",
    headers:{"Content-Type":"application/json"},
    body:JSON.stringify({visible:!v})
  });
  load();
};

window.delD=async id=>{
  if(!confirm("确定删除这份资料吗？删除后原文件也会一起删除。")) return;
  await fetch("/api/admin/documents/"+encodeURIComponent(id),{method:"DELETE"});
  load();
};

auth();
</script>
</body>
</html>`;

app.get("/", (_,res)=>res.type("html").send(homeHtml));
app.get("/admin.html", (_,res)=>res.type("html").send(adminHtml));
app.get("/internal", (_,res)=>res.type("html").send(internalResourceHtml));
app.get("/videos", (_,res)=>res.type("html").send(internalResourceHtml));

app.post("/api/login",(req,res)=>{
  if(String(req.body.password||"")===ADMIN_PASSWORD){
    req.session.isAdmin=true;
    return res.json({ok:true});
  }
  res.status(401).json({error:"密码错误"});
});

app.post("/api/logout",(req,res)=>{
  req.session.destroy(()=>res.json({ok:true}));
});

app.get("/api/me",(req,res)=>{
  res.json({isAdmin:Boolean(req.session?.isAdmin)});
});


app.get("/api/internal-access/me",(req,res)=>{
  res.json({authorized:Boolean(req.session?.internalAccess)});
});

app.post("/api/internal-access/login",(req,res)=>{
  if(!INTERNAL_ACCESS_PASSWORD){
    return res.status(503).json({error:"内部访问密码尚未配置"});
  }
  if(String(req.body.password||"")===INTERNAL_ACCESS_PASSWORD){
    req.session.internalAccess=true;
    return res.json({ok:true});
  }
  res.status(401).json({error:"密码错误"});
});

app.post("/api/internal-access/logout",(req,res)=>{
  if(req.session) req.session.internalAccess=false;
  res.json({ok:true});
});


app.get("/api/site-settings",(req,res)=>{
  const s=readSettings();
  res.json({
    announcement:s.announcement,
    submission:s.submission
  });
});

app.get("/api/admin/site-settings",adminOnly,(req,res)=>{
  res.json(readSettings());
});

app.patch("/api/admin/site-settings",adminOnly,(req,res)=>{
  const s=readSettings();

  if(req.body.announcement){
    const a=req.body.announcement;
    if("enabled" in a) s.announcement.enabled=Boolean(a.enabled);
    if("title" in a) s.announcement.title=clean(a.title,100)||"置顶公告";
    if("content" in a) s.announcement.content=clean(a.content,2000);
  }

  if(req.body.submission){
    const sub=req.body.submission;
    if("enabled" in sub) s.submission.enabled=Boolean(sub.enabled);
    if("title" in sub) s.submission.title=clean(sub.title,100)||"投稿邮箱";
    if("email" in sub) s.submission.email=clean(sub.email,200);
    if("content" in sub) s.submission.content=clean(sub.content,2000);
  }

  writeSettings(s);
  res.json({ok:true,settings:s});
});


app.get("/api/internal-resources",internalAccessOnly,(req,res)=>{
  const items=readInternalResources()
    .filter(v=>v.visible!==false)
    .sort((a,b)=>{
      const pinDiff=Number(Boolean(b.pinned))-Number(Boolean(a.pinned));
      if(pinDiff!==0)return pinDiff;
      const sortDiff=Number(b.sortOrder||0)-Number(a.sortOrder||0);
      if(sortDiff!==0)return sortDiff;
      return String(b.updatedAt||b.createdAt||"").localeCompare(String(a.updatedAt||a.createdAt||""));
    });

  res.json(items.map(v=>({
    id:v.id,
    title:v.title,
    category:v.category,
    description:v.description,
    originalName:v.originalName,
    type:v.type,
    contentType:v.contentType,
    resourceKind:v.resourceKind||classifyInternalResource(v.contentType,v.originalName),
    hasCover:Boolean(v.coverObjectKey),
    size:v.size,
    pinned:Boolean(v.pinned),
    accesses:Number(v.accesses||v.views||0),
    createdAt:v.createdAt,
    updatedAt:v.updatedAt
  })));
});

app.get("/api/admin/internal-resources",adminOnly,(req,res)=>{
  const items=readInternalResources().map(v=>({
    ...v,
    resourceKind:v.resourceKind||classifyInternalResource(v.contentType,v.originalName)
  }));
  res.json(
    items.sort((a,b)=>{
      const pinDiff=Number(Boolean(b.pinned))-Number(Boolean(a.pinned));
      if(pinDiff!==0)return pinDiff;
      const sortDiff=Number(b.sortOrder||0)-Number(a.sortOrder||0);
      if(sortDiff!==0)return sortDiff;
      return String(b.updatedAt||b.createdAt||"").localeCompare(String(a.updatedAt||a.createdAt||""));
    })
  );
});

app.get("/api/documents",(req,res)=>{
  const docs=readDocs()
    .filter(d=>d.visible!==false)
    .sort((a,b)=>{
      const pinDiff=Number(Boolean(b.pinned))-Number(Boolean(a.pinned));
      if(pinDiff!==0) return pinDiff;
      const recDiff=Number(Boolean(b.recommended))-Number(Boolean(a.recommended));
      if(recDiff!==0) return recDiff;
      const sortDiff=Number(b.sortOrder||0)-Number(a.sortOrder||0);
      if(sortDiff!==0) return sortDiff;
      return String(b.updatedAt||b.createdAt||"").localeCompare(String(a.updatedAt||a.createdAt||""));
    });
  res.json(docs);
});

app.get("/api/admin/documents",adminOnly,(req,res)=>{
  res.json(
    readDocs().sort((a,b)=>{
      const pinDiff=Number(Boolean(b.pinned))-Number(Boolean(a.pinned));
      if(pinDiff!==0) return pinDiff;
      const recDiff=Number(Boolean(b.recommended))-Number(Boolean(a.recommended));
      if(recDiff!==0) return recDiff;
      const sortDiff=Number(b.sortOrder||0)-Number(a.sortOrder||0);
      if(sortDiff!==0) return sortDiff;
      return String(b.updatedAt||b.createdAt||"").localeCompare(String(a.updatedAt||a.createdAt||""));
    })
  );
});

app.post("/api/admin/links",adminOnly,(req,res)=>{
  const title=clean(req.body.title,100);
  const category=clean(req.body.category,50)||"工具链接";
  const description=clean(req.body.description,500);
  const url=validHttpUrl(req.body.url);

  if(!title) return res.status(400).json({error:"链接名称不能为空"});
  if(!url) return res.status(400).json({error:"网址格式不正确，请填写以 http:// 或 https:// 开头的完整网址"});

  const docs=readDocs();
  const doc={
    id:crypto.randomUUID(),
    kind:"link",
    title,
    category,
    description,
    url,
    type:"LINK",
    size:0,
    downloads:0,
    visible:true,
    pinned:false,
    recommended:false,
    version:clean(req.body.version,50)||"V1.0",
    sortOrder:Number(req.body.sortOrder||0),
    createdAt:new Date().toISOString(),
    updatedAt:new Date().toISOString()
  };

  docs.push(doc);
  writeDocs(docs);
  res.json({ok:true,document:doc});
});



app.post("/api/admin/internal-resources/cover-presign",adminOnly,async(req,res)=>{
  if(!BUCKET_READY){
    return res.status(503).json({error:"Bucket 尚未连接完成"});
  }

  const filename=safeOriginalName(req.body.filename||"cover.jpg");
  const ext=path.extname(filename).toLowerCase();
  const allowedCover=new Set([".jpg",".jpeg",".png",".webp"]);
  if(!allowedCover.has(ext)){
    return res.status(400).json({error:"封面仅支持 JPG、PNG、WebP"});
  }

  const size=Number(req.body.size||0);
  if(!Number.isFinite(size)||size<=0){
    return res.status(400).json({error:"封面文件大小无效"});
  }
  if(size>20*1024*1024){
    return res.status(400).json({error:"封面图片不能超过20MB"});
  }

  const contentType=clean(req.body.contentType,120)||"image/jpeg";
  const key=`internal-covers/${new Date().toISOString().slice(0,10)}/${Date.now()}-${crypto.randomBytes(8).toString("hex")}${ext}`;

  try{
    const command=new PutObjectCommand({
      Bucket:BUCKET_NAME,
      Key:key,
      ContentType:contentType
    });
    const uploadUrl=await getSignedUrl(s3,command,{expiresIn:3600});
    res.json({ok:true,key,uploadUrl});
  }catch(err){
    console.error("生成内部封面上传地址失败",err);
    res.status(500).json({error:"无法生成封面上传地址"});
  }
});

app.post("/api/admin/internal-resources/cover-delete",adminOnly,async(req,res)=>{
  const key=String(req.body.coverObjectKey||"");
  if(!key.startsWith("internal-covers/")) return res.json({ok:true});
  try{
    if(BUCKET_READY){
      await s3.send(new DeleteObjectCommand({Bucket:BUCKET_NAME,Key:key}));
    }
  }catch{}
  res.json({ok:true});
});

app.post("/api/admin/internal-resources/upload-init",adminOnly,async(req,res)=>{
  if(!BUCKET_READY){
    return res.status(503).json({error:"Bucket 尚未连接完成"});
  }

  const filename=safeOriginalName(req.body.filename);
  const size=Number(req.body.size||0);
  const contentType=clean(req.body.contentType,180)||"application/octet-stream";

  if(!filename) return res.status(400).json({error:"文件名无效"});
  if(!Number.isFinite(size)||size<=0) return res.status(400).json({error:"文件大小无效"});

  const ext=path.extname(filename);
  const key=`internal-resources/${new Date().toISOString().slice(0,10)}/${Date.now()}-${crypto.randomBytes(10).toString("hex")}${ext}`;

  try{
    const SINGLE_UPLOAD_THRESHOLD=128*1024*1024;

    if(size<=SINGLE_UPLOAD_THRESHOLD){
      const command=new PutObjectCommand({
        Bucket:BUCKET_NAME,
        Key:key,
        ContentType:contentType
      });
      const uploadUrl=await getSignedUrl(s3,command,{expiresIn:3600});
      return res.json({ok:true,mode:"single",key,uploadUrl});
    }

    const create=await s3.send(new CreateMultipartUploadCommand({
      Bucket:BUCKET_NAME,
      Key:key,
      ContentType:contentType
    }));

    const minPart=64*1024*1024;
    const dynamicPart=Math.ceil(size/9500);
    const partSize=Math.max(minPart,Math.ceil(dynamicPart/(1024*1024))*(1024*1024));

    res.json({
      ok:true,
      mode:"multipart",
      key,
      uploadId:create.UploadId,
      partSize
    });
  }catch(err){
    console.error("准备内部资料上传失败",err);
    res.status(500).json({error:"无法准备上传"});
  }
});

app.post("/api/admin/internal-resources/upload-part",adminOnly,async(req,res)=>{
  if(!BUCKET_READY) return res.status(503).json({error:"Bucket 尚未连接完成"});

  const key=String(req.body.key||"");
  const uploadId=String(req.body.uploadId||"");
  const partNumber=Number(req.body.partNumber||0);

  if(!key.startsWith("internal-resources/")||!uploadId||!Number.isInteger(partNumber)||partNumber<1||partNumber>10000){
    return res.status(400).json({error:"分片参数无效"});
  }

  try{
    const command=new UploadPartCommand({
      Bucket:BUCKET_NAME,
      Key:key,
      UploadId:uploadId,
      PartNumber:partNumber
    });
    const uploadUrl=await getSignedUrl(s3,command,{expiresIn:3600});
    res.json({ok:true,uploadUrl});
  }catch(err){
    console.error("生成分片上传地址失败",err);
    res.status(500).json({error:"无法生成分片上传地址"});
  }
});

app.post("/api/admin/internal-resources/upload-complete-multipart",adminOnly,async(req,res)=>{
  if(!BUCKET_READY) return res.status(503).json({error:"Bucket 尚未连接完成"});

  const key=String(req.body.key||"");
  const uploadId=String(req.body.uploadId||"");
  const parts=Array.isArray(req.body.parts)?req.body.parts:[];

  if(!key.startsWith("internal-resources/")||!uploadId||!parts.length){
    return res.status(400).json({error:"分片合并参数无效"});
  }

  const cleanParts=parts
    .map(p=>({PartNumber:Number(p.PartNumber),ETag:String(p.ETag||"")}))
    .filter(p=>Number.isInteger(p.PartNumber)&&p.PartNumber>0&&p.ETag)
    .sort((a,b)=>a.PartNumber-b.PartNumber);

  if(cleanParts.length!==parts.length){
    return res.status(400).json({error:"分片信息不完整"});
  }

  try{
    await s3.send(new CompleteMultipartUploadCommand({
      Bucket:BUCKET_NAME,
      Key:key,
      UploadId:uploadId,
      MultipartUpload:{Parts:cleanParts}
    }));
    res.json({ok:true});
  }catch(err){
    console.error("合并内部资料分片失败",err);
    res.status(500).json({error:"合并分片失败"});
  }
});

app.post("/api/admin/internal-resources/upload-abort",adminOnly,async(req,res)=>{
  if(!BUCKET_READY)return res.json({ok:true});

  const key=String(req.body.key||"");
  const uploadId=String(req.body.uploadId||"");
  if(!key.startsWith("internal-resources/")||!uploadId)return res.json({ok:true});

  try{
    await s3.send(new AbortMultipartUploadCommand({
      Bucket:BUCKET_NAME,
      Key:key,
      UploadId:uploadId
    }));
  }catch{}
  res.json({ok:true});
});

app.post("/api/admin/internal-resources/finalize",adminOnly,async(req,res)=>{
  if(!BUCKET_READY){
    return res.status(503).json({error:"Bucket 尚未连接完成"});
  }

  const key=String(req.body.key||"").trim();
  const originalName=safeOriginalName(req.body.originalName);
  const declaredSize=Number(req.body.size||0);

  if(!key.startsWith("internal-resources/")){
    return res.status(400).json({error:"文件标识无效"});
  }

  try{
    const head=await s3.send(new HeadObjectCommand({Bucket:BUCKET_NAME,Key:key}));
    const actualSize=Number(head.ContentLength||0);
    if(!actualSize)return res.status(400).json({error:"Bucket 中未找到上传文件"});

    if(declaredSize&&actualSize!==declaredSize){
      return res.status(400).json({error:"文件大小校验失败，请重新上传"});
    }

    const items=readInternalResources();
    const now=new Date().toISOString();
    const ext=path.extname(originalName).replace(".","").toUpperCase();
    const contentType=clean(head.ContentType||req.body.contentType,180)||"application/octet-stream";

    const item={
      id:crypto.randomUUID(),
      storage:"bucket",
      objectKey:key,
      title:clean(req.body.title,160)||originalName,
      category:clean(req.body.category,80)||"内部资料",
      description:clean(req.body.description,1500),
      originalName,
      type:ext||"FILE",
      contentType,
      resourceKind:classifyInternalResource(contentType,originalName),
      coverObjectKey:String(req.body.coverObjectKey||"").startsWith("internal-covers/") ? String(req.body.coverObjectKey) : "",
      size:actualSize,
      accesses:0,
      visible:true,
      pinned:false,
      sortOrder:Number(req.body.sortOrder||0),
      createdAt:now,
      updatedAt:now
    };

    items.push(item);
    writeInternalResources(items);
    res.json({ok:true,item});
  }catch(err){
    console.error("确认内部资料上传失败",err);
    res.status(500).json({error:"确认上传失败，请稍后重试"});
  }
});

app.patch("/api/admin/internal-resources/:id",adminOnly,(req,res)=>{
  const items=readInternalResources();
  const item=items.find(x=>x.id===req.params.id);
  if(!item)return res.status(404).json({error:"内部资料不存在"});

  if("title" in req.body){
    const title=clean(req.body.title,160);
    if(!title)return res.status(400).json({error:"资料名称不能为空"});
    item.title=title;
  }
  if("category" in req.body)item.category=clean(req.body.category,80)||"内部资料";
  if("description" in req.body)item.description=clean(req.body.description,1500);
  if("visible" in req.body)item.visible=Boolean(req.body.visible);
  if("pinned" in req.body)item.pinned=Boolean(req.body.pinned);
  if("sortOrder" in req.body){
    const n=Number(req.body.sortOrder||0);
    item.sortOrder=Number.isFinite(n)?n:0;
  }
  item.resourceKind=item.resourceKind||classifyInternalResource(item.contentType,item.originalName);
  item.updatedAt=new Date().toISOString();
  writeInternalResources(items);
  res.json({ok:true,item});
});

app.get("/api/admin/internal-resources/:id/source-url",adminOnly,async(req,res)=>{
  const items=readInternalResources();
  const item=items.find(x=>x.id===req.params.id);
  if(!item)return res.status(404).json({error:"内部资料不存在"});
  if((item.resourceKind||classifyInternalResource(item.contentType,item.originalName))!=="video"){
    return res.status(400).json({error:"这不是视频资料"});
  }
  if(!BUCKET_READY)return res.status(503).json({error:"Bucket 尚未连接"});

  try{
    const command=new GetObjectCommand({
      Bucket:BUCKET_NAME,
      Key:item.objectKey,
      ResponseContentDisposition:"inline",
      ResponseContentType:item.contentType||"video/mp4"
    });
    const url=await getSignedUrl(s3,command,{expiresIn:1800});
    res.json({ok:true,url});
  }catch(err){
    console.error("生成原视频临时地址失败",err);
    res.status(500).json({error:"暂时无法读取原视频"});
  }
});

app.patch("/api/admin/internal-resources/:id/cover",adminOnly,async(req,res)=>{
  const items=readInternalResources();
  const item=items.find(x=>x.id===req.params.id);
  if(!item)return res.status(404).json({error:"内部资料不存在"});

  const newKey=String(req.body.coverObjectKey||"");
  if(!newKey.startsWith("internal-covers/")){
    return res.status(400).json({error:"封面标识无效"});
  }

  const oldKey=String(item.coverObjectKey||"");
  item.coverObjectKey=newKey;
  item.updatedAt=new Date().toISOString();
  writeInternalResources(items);

  if(oldKey&&oldKey!==newKey&&BUCKET_READY){
    try{
      await s3.send(new DeleteObjectCommand({Bucket:BUCKET_NAME,Key:oldKey}));
    }catch(err){
      console.error("删除旧封面失败",err);
    }
  }

  res.json({ok:true,item});
});

app.delete("/api/admin/internal-resources/:id",adminOnly,async(req,res)=>{
  const items=readInternalResources();
  const i=items.findIndex(x=>x.id===req.params.id);
  if(i<0)return res.status(404).json({error:"内部资料不存在"});

  const item=items[i];
  try{
    if(item.storage==="bucket"&&item.objectKey&&BUCKET_READY){
      await s3.send(new DeleteObjectCommand({Bucket:BUCKET_NAME,Key:item.objectKey}));
    }
    if(item.coverObjectKey&&BUCKET_READY){
      try{
        await s3.send(new DeleteObjectCommand({Bucket:BUCKET_NAME,Key:item.coverObjectKey}));
      }catch{}
    }
  }catch(err){
    console.error("删除内部资料实体失败",err);
    return res.status(500).json({error:"删除实体文件失败，请稍后重试"});
  }

  items.splice(i,1);
  writeInternalResources(items);
  res.json({ok:true});
});

app.post("/api/admin/uploads/presign",adminOnly,async(req,res)=>{
  if(!BUCKET_READY){
    return res.status(503).json({error:"Bucket 尚未连接完成"});
  }

  const filename=safeOriginalName(req.body.filename);
  const size=Number(req.body.size||0);
  const ext=path.extname(filename).toLowerCase();

  if(!allowed.has(ext)){
    return res.status(400).json({error:"不支持该文件类型"});
  }

  if(!Number.isFinite(size) || size<=0){
    return res.status(400).json({error:"文件大小无效"});
  }

  if(size > MAX_UPLOAD_MB * 1024 * 1024){
    return res.status(400).json({error:`单个文件不能超过${MAX_UPLOAD_MB}MB`});
  }

  const key=`uploads/${new Date().toISOString().slice(0,10)}/${Date.now()}-${crypto.randomBytes(8).toString("hex")}${ext}`;

  try{
    const command=new PutObjectCommand({
      Bucket:BUCKET_NAME,
      Key:key,
      ContentType:clean(req.body.contentType,120)||"application/octet-stream"
    });

    const uploadUrl=await getSignedUrl(s3,command,{expiresIn:3600});
    res.json({ok:true,key,uploadUrl});
  }catch(err){
    console.error("生成 Bucket 上传地址失败",err);
    res.status(500).json({error:"无法生成上传地址"});
  }
});

app.post("/api/admin/uploads/complete",adminOnly,async(req,res)=>{
  if(!BUCKET_READY){
    return res.status(503).json({error:"Bucket 尚未连接完成"});
  }

  const key=String(req.body.key||"").trim();
  const originalName=safeOriginalName(req.body.originalName);
  const title=clean(req.body.title,100)||originalName;
  const category=clean(req.body.category,50)||"其他资料";
  const description=clean(req.body.description,500);
  const declaredSize=Number(req.body.size||0);

  if(!key.startsWith("uploads/")){
    return res.status(400).json({error:"文件标识无效"});
  }

  try{
    const head=await s3.send(new HeadObjectCommand({
      Bucket:BUCKET_NAME,
      Key:key
    }));

    const actualSize=Number(head.ContentLength||0);
    if(!actualSize){
      return res.status(400).json({error:"Bucket 中未找到上传文件"});
    }

    if(declaredSize && actualSize!==declaredSize){
      return res.status(400).json({error:"文件大小校验失败，请重新上传"});
    }

    const docs=readDocs();
    const ext=path.extname(originalName).replace(".","").toUpperCase();

    const doc={
      id:crypto.randomUUID(),
      kind:"file",
      storage:"bucket",
      objectKey:key,
      title,
      category,
      description,
      originalName,
      type:ext||clean(req.body.type,20)||"FILE",
      size:actualSize,
      downloads:0,
      visible:true,
      pinned:false,
      recommended:false,
      version:clean(req.body.version,50)||"V1.0",
      sortOrder:Number(req.body.sortOrder||0),
      createdAt:new Date().toISOString(),
      updatedAt:new Date().toISOString()
    };

    docs.push(doc);
    writeDocs(docs);
    res.json({ok:true,document:doc});
  }catch(err){
    console.error("确认 Bucket 上传失败",err);
    res.status(500).json({error:"确认上传失败，请稍后重试"});
  }
});

app.post("/api/admin/documents",adminOnly,upload.single("file"),(req,res)=>{
  if(!req.file) return res.status(400).json({error:"请选择文档"});

  const docs=readDocs();
  const ext=path.extname(req.file.originalname).replace(".","").toUpperCase();

  const doc={
    id:crypto.randomUUID(),
    kind:"file",
    title:clean(req.body.title,100)||req.file.originalname,
    category:clean(req.body.category,50)||"其他资料",
    description:clean(req.body.description,500),
    originalName:req.file.originalname,
    storedName:req.file.filename,
    type:ext||"FILE",
    size:req.file.size,
    downloads:0,
    visible:true,
    pinned:false,
    recommended:false,
    version:clean(req.body.version,50)||"V1.0",
    sortOrder:Number(req.body.sortOrder||0),
    createdAt:new Date().toISOString(),
    updatedAt:new Date().toISOString()
  };

  docs.push(doc);
  writeDocs(docs);
  res.json({ok:true,document:doc});
});

app.patch("/api/admin/documents/:id",adminOnly,(req,res)=>{
  const docs=readDocs();
  const d=docs.find(x=>x.id===req.params.id);

  if(!d) return res.status(404).json({error:"文档不存在"});

  if("title" in req.body) {
    const v=clean(req.body.title,100);
    if(!v) return res.status(400).json({error:"文档名称不能为空"});
    d.title=v;
  }

  if("category" in req.body) {
    d.category=clean(req.body.category,50)||"其他资料";
  }

  if("description" in req.body) {
    d.description=clean(req.body.description,500);
  }

  if("visible" in req.body) {
    d.visible=Boolean(req.body.visible);
  }

  if("pinned" in req.body) {
    d.pinned=Boolean(req.body.pinned);
  }

  if("recommended" in req.body) {
    d.recommended=Boolean(req.body.recommended);
  }

  if("version" in req.body) {
    d.version=clean(req.body.version,50)||"V1.0";
  }

  if("sortOrder" in req.body) {
    const sortOrder=Number(req.body.sortOrder||0);
    d.sortOrder=Number.isFinite(sortOrder)?sortOrder:0;
  }

  if("url" in req.body && d.kind==="link") {
    const url=validHttpUrl(req.body.url);
    if(!url) return res.status(400).json({error:"网址格式不正确，请填写完整的 http:// 或 https:// 地址"});
    d.url=url;
  }

  d.updatedAt=new Date().toISOString();
  writeDocs(docs);

  res.json({ok:true,document:d});
});

app.delete("/api/admin/documents/:id",adminOnly,async(req,res)=>{
  const docs=readDocs();
  const i=docs.findIndex(x=>x.id===req.params.id);

  if(i<0) return res.status(404).json({error:"文档不存在"});

  const d=docs[i];

  try{
    if(d.kind==="link"){
      // 外部链接没有实体文件
    }else if(d.storage==="bucket" && d.objectKey && BUCKET_READY){
      await s3.send(new DeleteObjectCommand({
        Bucket:BUCKET_NAME,
        Key:d.objectKey
      }));
    }else if(d.storedName){
      const f=path.join(UPLOAD_DIR,d.storedName);
      if(fs.existsSync(f)) fs.unlinkSync(f);
    }
  }catch(err){
    console.error("删除实体文件失败",err);
    return res.status(500).json({error:"删除文件失败，请稍后重试"});
  }

  docs.splice(i,1);
  writeDocs(docs);
  res.json({ok:true});
});

app.get("/go/:id",(req,res)=>{
  const docs=readDocs();
  const d=docs.find(x=>x.id===req.params.id && x.visible!==false && x.kind==="link");

  if(!d) return res.status(404).send("链接不存在");

  const url=validHttpUrl(d.url);
  if(!url) return res.status(400).send("链接地址无效");

  d.downloads=Number(d.downloads||0)+1;
  writeDocs(docs);

  res.redirect(url);
});


function markInternalAccess(id){
  const items=readInternalResources();
  const item=items.find(x=>x.id===id);
  if(item){
    item.accesses=Number(item.accesses||item.views||0)+1;
    writeInternalResources(items);
  }
}

app.get("/internal-resource/cover/:id",internalAccessOnly,async(req,res)=>{
  const items=readInternalResources();
  const item=items.find(x=>x.id===req.params.id&&x.visible!==false);
  if(!item||!item.coverObjectKey)return res.status(404).send("封面不存在");
  if(!BUCKET_READY)return res.status(503).send("Bucket 尚未连接");

  try{
    const command=new GetObjectCommand({
      Bucket:BUCKET_NAME,
      Key:item.coverObjectKey,
      ResponseContentDisposition:"inline"
    });
    const url=await getSignedUrl(s3,command,{expiresIn:1800});
    res.redirect(url);
  }catch(err){
    console.error("生成内部封面地址失败",err);
    res.status(500).send("封面暂时无法显示");
  }
});

app.get("/internal-resource/open/:id",internalAccessOnly,async(req,res)=>{
  const items=readInternalResources();
  const item=items.find(x=>x.id===req.params.id&&x.visible!==false);
  if(!item)return res.status(404).send("内部资料不存在");
  if(!BUCKET_READY)return res.status(503).send("Bucket 尚未连接");

  const kind=item.resourceKind||classifyInternalResource(item.contentType,item.originalName);
  if(!["video","audio","image","pdf","text"].includes(kind)){
    return res.status(415).send("该文件类型不支持在线查看，请使用下载");
  }

  try{
    const command=new GetObjectCommand({
      Bucket:BUCKET_NAME,
      Key:item.objectKey,
      ResponseContentDisposition:"inline",
      ResponseContentType:item.contentType||undefined
    });
    const url=await getSignedUrl(s3,command,{expiresIn:1800});
    markInternalAccess(item.id);
    res.redirect(url);
  }catch(err){
    console.error("生成内部资料查看地址失败",err);
    res.status(500).send("暂时无法打开该资料");
  }
});

app.get("/internal-resource/download/:id",internalAccessOnly,async(req,res)=>{
  const items=readInternalResources();
  const item=items.find(x=>x.id===req.params.id&&x.visible!==false);
  if(!item)return res.status(404).send("内部资料不存在");
  if(!BUCKET_READY)return res.status(503).send("Bucket 尚未连接");

  try{
    const filename=safeOriginalName(item.originalName||item.title||"download");
    const command=new GetObjectCommand({
      Bucket:BUCKET_NAME,
      Key:item.objectKey,
      ResponseContentDisposition:`attachment; filename*=UTF-8''${encodeURIComponent(filename)}`
    });
    const url=await getSignedUrl(s3,command,{expiresIn:1800});
    markInternalAccess(item.id);
    res.redirect(url);
  }catch(err){
    console.error("生成内部资料下载地址失败",err);
    res.status(500).send("暂时无法下载该资料");
  }
});

app.get("/preview/:id",async(req,res)=>{
  const docs=readDocs();
  const d=docs.find(x=>x.id===req.params.id && x.visible!==false && x.kind!=="link");

  if(!d) return res.status(404).send("文件不存在");

  const type=String(d.type||"").toUpperCase();
  if(type!=="PDF" && type!=="TXT"){
    return res.status(415).send("该文件类型暂不支持在线预览");
  }

  const contentType=type==="PDF"?"application/pdf":"text/plain; charset=utf-8";

  try{
    if(d.storage==="bucket" && d.objectKey){
      if(!BUCKET_READY) return res.status(503).send("Bucket 尚未连接");

      const command=new GetObjectCommand({
        Bucket:BUCKET_NAME,
        Key:d.objectKey,
        ResponseContentDisposition:"inline",
        ResponseContentType:contentType
      });

      const url=await getSignedUrl(s3,command,{expiresIn:900});
      return res.redirect(url);
    }

    const f=path.join(UPLOAD_DIR,d.storedName||"");
    if(!d.storedName || !fs.existsSync(f)) return res.status(404).send("文件已丢失");

    res.setHeader("Content-Type",contentType);
    res.setHeader("Content-Disposition","inline");
    return res.sendFile(f);
  }catch(err){
    console.error("预览失败",err);
    res.status(500).send("预览失败，请稍后重试");
  }
});

app.get("/download/:id",async(req,res)=>{
  const docs=readDocs();
  const d=docs.find(x=>x.id===req.params.id && x.visible!==false && x.kind!=="link");

  if(!d) return res.status(404).send("文件不存在");

  try{
    if(d.storage==="bucket" && d.objectKey){
      if(!BUCKET_READY) return res.status(503).send("Bucket 尚未连接");

      const filename=safeOriginalName(d.originalName||d.title||"download");
      const command=new GetObjectCommand({
        Bucket:BUCKET_NAME,
        Key:d.objectKey,
        ResponseContentDisposition:`attachment; filename*=UTF-8''${encodeURIComponent(filename)}`
      });

      const url=await getSignedUrl(s3,command,{expiresIn:900});

      d.downloads=Number(d.downloads||0)+1;
      writeDocs(docs);

      return res.redirect(url);
    }

    const f=path.join(UPLOAD_DIR,d.storedName||"");
    if(!d.storedName || !fs.existsSync(f)) return res.status(404).send("文件已丢失");

    d.downloads=Number(d.downloads||0)+1;
    writeDocs(docs);
    return res.download(f,d.originalName);
  }catch(err){
    console.error("下载失败",err);
    res.status(500).send("下载失败，请稍后重试");
  }
});

app.use((err,req,res,next)=>{
  console.error(err);
  if(err?.code==="LIMIT_FILE_SIZE"){
    return res.status(400).json({error:`单个文件不能超过${MAX_UPLOAD_MB}MB`});
  }
  res.status(400).json({error:err?.message||"操作失败"});
});

app.listen(PORT,()=>console.log("网站已启动，端口："+PORT));
