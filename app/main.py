import os, sqlite3, hashlib, secrets, shutil, csv, io, json
from datetime import datetime, date, timedelta
from pathlib import Path
from typing import Optional
from fastapi import FastAPI, Request, HTTPException, Response
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from itsdangerous import URLSafeSerializer, BadSignature

ROOT = Path(__file__).resolve().parent.parent
DB = Path(os.getenv("SULTAN_DB_PATH", str(ROOT / "sultan.db"))).expanduser()
APP_ENV = os.getenv("APP_ENV", "development").strip().lower()
SECRET = os.getenv("SULTAN_SECRET_KEY", "").strip()
if APP_ENV == "production" and (len(SECRET) < 32 or SECRET.startswith("REPLACE_") or SECRET == "CHANGE_THIS_SECRET_BEFORE_PUBLIC_DEPLOYMENT"):
    raise RuntimeError("Production requires a unique SULTAN_SECRET_KEY of at least 32 characters")
INITIAL_ADMIN_PASSWORD = os.getenv("SULTAN_INITIAL_ADMIN_PASSWORD", "").strip()
if APP_ENV == "production" and len(INITIAL_ADMIN_PASSWORD) < 12:
    raise RuntimeError("Production first-run requires SULTAN_INITIAL_ADMIN_PASSWORD with at least 12 characters")
if not SECRET:
    SECRET = secrets.token_urlsafe(48)
signer = URLSafeSerializer(SECRET, salt="sultan-session")
app = FastAPI(title="SULTAN SHOP MANAGEMENT", version="1.0.0")
app.mount("/static", StaticFiles(directory=str(ROOT/"app"/"static")), name="static")

def connect():
    DB.parent.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(DB, timeout=20)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA foreign_keys=ON")
    c.execute("PRAGMA journal_mode=WAL")
    return c

def hash_pw(pw, salt=None):
    salt = salt or secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, 310000)
    return salt.hex()+":"+dk.hex()

def verify_pw(pw, stored):
    try:
        salt, expected = stored.split(":")
        actual = hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(salt), 310000).hex()
        return secrets.compare_digest(actual, expected)
    except Exception:
        return False

def init_db():
    with connect() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS login_attempts(
            ip TEXT NOT NULL, username TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0,
            window_start TEXT NOT NULL, locked_until TEXT DEFAULT '',
            PRIMARY KEY(ip, username)
        );
        CREATE TABLE IF NOT EXISTS branches(id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE, active INTEGER DEFAULT 1);
        CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, password TEXT NOT NULL, full_name TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'employee', branch_id INTEGER, active INTEGER DEFAULT 1, permissions TEXT DEFAULT '', FOREIGN KEY(branch_id) REFERENCES branches(id));
        CREATE TABLE IF NOT EXISTS products(id INTEGER PRIMARY KEY, name TEXT NOT NULL, category TEXT DEFAULT 'أخرى', description TEXT DEFAULT '', barcode TEXT UNIQUE, purchase_price REAL NOT NULL DEFAULT 0, selling_price REAL NOT NULL DEFAULT 0, min_stock REAL NOT NULL DEFAULT 0, active INTEGER DEFAULT 1);
        CREATE TABLE IF NOT EXISTS stock(id INTEGER PRIMARY KEY, product_id INTEGER NOT NULL, branch_id INTEGER NOT NULL, quantity REAL NOT NULL DEFAULT 0, UNIQUE(product_id,branch_id), FOREIGN KEY(product_id) REFERENCES products(id), FOREIGN KEY(branch_id) REFERENCES branches(id));
        CREATE TABLE IF NOT EXISTS sales(id INTEGER PRIMARY KEY, invoice_no TEXT UNIQUE NOT NULL, branch_id INTEGER NOT NULL, user_id INTEGER NOT NULL, subtotal REAL NOT NULL, discount REAL NOT NULL, total REAL NOT NULL, paid REAL NOT NULL, payment_method TEXT NOT NULL, created_at TEXT NOT NULL, FOREIGN KEY(branch_id) REFERENCES branches(id));
        CREATE TABLE IF NOT EXISTS sale_items(id INTEGER PRIMARY KEY, sale_id INTEGER NOT NULL, product_id INTEGER NOT NULL, name TEXT NOT NULL, qty REAL NOT NULL, unit_price REAL NOT NULL, line_total REAL NOT NULL, unit_cost REAL NOT NULL DEFAULT 0, FOREIGN KEY(sale_id) REFERENCES sales(id), FOREIGN KEY(product_id) REFERENCES products(id));
        CREATE TABLE IF NOT EXISTS expenses(id INTEGER PRIMARY KEY, branch_id INTEGER NOT NULL, user_id INTEGER NOT NULL, title TEXT NOT NULL, category TEXT NOT NULL, amount REAL NOT NULL, note TEXT DEFAULT '', created_at TEXT NOT NULL, FOREIGN KEY(branch_id) REFERENCES branches(id));
        CREATE TABLE IF NOT EXISTS debts(id INTEGER PRIMARY KEY, branch_id INTEGER NOT NULL, customer TEXT NOT NULL, phone TEXT DEFAULT '', original REAL NOT NULL, paid REAL NOT NULL DEFAULT 0, due_date TEXT DEFAULT '', note TEXT DEFAULT '', created_at TEXT NOT NULL, FOREIGN KEY(branch_id) REFERENCES branches(id));
        CREATE TABLE IF NOT EXISTS debt_payments(id INTEGER PRIMARY KEY, debt_id INTEGER NOT NULL, amount REAL NOT NULL, user_id INTEGER NOT NULL, created_at TEXT NOT NULL, FOREIGN KEY(debt_id) REFERENCES debts(id));
        CREATE TABLE IF NOT EXISTS repairs(id INTEGER PRIMARY KEY, branch_id INTEGER NOT NULL, customer TEXT NOT NULL, phone TEXT DEFAULT '', item TEXT NOT NULL, issue TEXT DEFAULT '', cost REAL NOT NULL DEFAULT 0, paid REAL NOT NULL DEFAULT 0, status TEXT DEFAULT 'مستلم', note TEXT DEFAULT '', created_at TEXT NOT NULL, user_id INTEGER NOT NULL, FOREIGN KEY(branch_id) REFERENCES branches(id));
        CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY, user_id INTEGER, branch_id INTEGER, action TEXT NOT NULL, details TEXT DEFAULT '', created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS stock_movements(id INTEGER PRIMARY KEY, product_id INTEGER NOT NULL, branch_id INTEGER NOT NULL, user_id INTEGER NOT NULL, kind TEXT NOT NULL, quantity REAL NOT NULL, reference TEXT DEFAULT '', note TEXT DEFAULT '', created_at TEXT NOT NULL, FOREIGN KEY(product_id) REFERENCES products(id));
        CREATE TABLE IF NOT EXISTS purchases(id INTEGER PRIMARY KEY, reference TEXT UNIQUE NOT NULL, branch_id INTEGER NOT NULL, user_id INTEGER NOT NULL, total REAL NOT NULL, created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS purchase_items(id INTEGER PRIMARY KEY, purchase_id INTEGER NOT NULL, product_id INTEGER NOT NULL, qty REAL NOT NULL, unit_cost REAL NOT NULL, FOREIGN KEY(purchase_id) REFERENCES purchases(id));
        CREATE TABLE IF NOT EXISTS returns(id INTEGER PRIMARY KEY, sale_id INTEGER NOT NULL, sale_item_id INTEGER NOT NULL, branch_id INTEGER NOT NULL, user_id INTEGER NOT NULL, qty REAL NOT NULL, amount REAL NOT NULL, refund_method TEXT NOT NULL, reason TEXT DEFAULT '', created_at TEXT NOT NULL, UNIQUE(sale_item_id, id), FOREIGN KEY(sale_id) REFERENCES sales(id));
        CREATE TABLE IF NOT EXISTS transfers(id INTEGER PRIMARY KEY, product_id INTEGER NOT NULL, from_branch INTEGER NOT NULL, to_branch INTEGER NOT NULL, qty REAL NOT NULL, status TEXT NOT NULL DEFAULT 'pending', requested_by INTEGER NOT NULL, approved_by INTEGER, note TEXT DEFAULT '', created_at TEXT NOT NULL, decided_at TEXT);
        CREATE TABLE IF NOT EXISTS cash_closings(id INTEGER PRIMARY KEY, branch_id INTEGER NOT NULL, user_id INTEGER NOT NULL, business_date TEXT NOT NULL, cash_expected REAL NOT NULL, cash_actual REAL NOT NULL, other_payments REAL NOT NULL, expenses REAL NOT NULL, returns REAL NOT NULL, difference REAL NOT NULL, note TEXT DEFAULT '', created_at TEXT NOT NULL, UNIQUE(branch_id,business_date));
        """)
        sale_item_cols = {r["name"] for r in c.execute("PRAGMA table_info(sale_items)")}
        if "unit_cost" not in sale_item_cols:
            c.execute("ALTER TABLE sale_items ADD COLUMN unit_cost REAL NOT NULL DEFAULT 0")
            c.execute("UPDATE sale_items SET unit_cost=COALESCE((SELECT purchase_price FROM products WHERE products.id=sale_items.product_id),0)")
        user_cols = {r["name"] for r in c.execute("PRAGMA table_info(users)")}
        if "session_version" not in user_cols:
            c.execute("ALTER TABLE users ADD COLUMN session_version INTEGER NOT NULL DEFAULT 0")
        if c.execute("SELECT COUNT(*) n FROM branches").fetchone()["n"] == 0:
            c.execute("INSERT INTO branches(name) VALUES(?)", ("الفرع الرئيسي",))
        if c.execute("SELECT COUNT(*) n FROM users").fetchone()["n"] == 0:
            bid = c.execute("SELECT id FROM branches ORDER BY id LIMIT 1").fetchone()["id"]
            first_password = INITIAL_ADMIN_PASSWORD if APP_ENV == "production" else (INITIAL_ADMIN_PASSWORD or "ChangeMe123!")
            c.execute("INSERT INTO users(username,password,full_name,role,branch_id) VALUES(?,?,?,?,?)",
                      ("admin", hash_pw(first_password), "مالك النظام", "owner", bid))
init_db()

@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(self), microphone=(), geolocation=()"
    if request.url.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
    return response

def now(): return datetime.now().isoformat(timespec="seconds")
def current_user(request):
    token = request.cookies.get("sultan_session")
    if not token: raise HTTPException(401, "يرجى تسجيل الدخول")
    try: uid = signer.loads(token)["uid"]
    except (BadSignature, Exception): raise HTTPException(401, "جلسة غير صالحة")
    with connect() as c:
        u = c.execute("SELECT id,username,full_name,role,branch_id,active,permissions,session_version FROM users WHERE id=?", (uid,)).fetchone()
    if not u or not u["active"]: raise HTTPException(401, "الحساب غير نشط")
    try:
        if int(signer.loads(token).get("sv", -1)) != int(u["session_version"]):
            raise HTTPException(401, "انتهت صلاحية الجلسة؛ يرجى تسجيل الدخول مجدداً")
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(401, "جلسة غير صالحة")
    user = dict(u)
    # Enforce module permissions on the server for every API request.
    if user["role"] != "owner":
        path = request.url.path
        method = request.method.upper()
        rules = [
            ("/api/products", "products"),
            ("/api/sales", "sales"),
            ("/api/expenses", "expenses"),
            ("/api/debts", "debts"),
            ("/api/repairs", "repairs"),
            ("/api/purchases", "purchases"),
            ("/api/transfers", "transfers"),
            ("/api/cash-closings", "cash"),
            ("/api/stock-movements", "inventory"),
            ("/api/reports", "reports"),
            ("/api/notifications", "dashboard"),
            ("/api/dashboard", "dashboard"),
        ]
        permission = next((key for prefix, key in rules if path == prefix or path.startswith(prefix + "/")), None)
        if permission:
            try: allowed = set(json.loads(user.get("permissions") or "[]"))
            except Exception: allowed = set()
            # Existing employee accounts retain a conservative operational baseline.
            if not user.get("permissions"):
                allowed = {"sales", "dashboard"}
            if permission not in allowed:
                raise HTTPException(403, "ليست لديك صلاحية لهذه العملية")
    return user

def require_owner(u):
    if u["role"] != "owner": raise HTTPException(403, "هذه العملية للمالك فقط")
def scope_branch(u, requested=None):
    if requested is not None:
        try:
            requested = int(requested)
        except (TypeError, ValueError):
            raise HTTPException(400, "معرّف الفرع غير صالح")
        if requested <= 0:
            raise HTTPException(400, "معرّف الفرع غير صالح")
    if u["role"] == "owner":
        if requested is not None:
            with connect() as c:
                if not c.execute("SELECT 1 FROM branches WHERE id=? AND active=1", (requested,)).fetchone():
                    raise HTTPException(404, "الفرع غير موجود أو غير نشط")
        return requested
    if requested is not None and requested != int(u["branch_id"]):
        raise HTTPException(403, "لا تملك صلاحية الوصول لهذا الفرع")
    return u["branch_id"]
def audit(c,u,action,details=""):
    c.execute("INSERT INTO audit(user_id,branch_id,action,details,created_at) VALUES(?,?,?,?,?)",
              (u["id"],u["branch_id"],action,details,now()))
def num(v, label):
    try:
        x=float(v)
        if x < 0 or x != x or x == float("inf"): raise ValueError()
        return x
    except Exception: raise HTTPException(400, f"قيمة غير صحيحة: {label}")

@app.get("/healthz")
def healthz():
    try:
        with connect() as c:
            c.execute("SELECT 1").fetchone()
        return {"status": "ok"}
    except sqlite3.Error:
        raise HTTPException(503, "database unavailable")

@app.get("/")
def home(): return FileResponse(ROOT/"app"/"static"/"index.html")

@app.post("/api/login")
async def login(request: Request, response: Response):
    d=await request.json()
    username=str(d.get("username", "")).strip()[:120]
    password=str(d.get("password", ""))
    ip=request.client.host if request.client else "unknown"
    stamp=now()
    failed=False
    with connect() as c:
        attempt=c.execute("SELECT * FROM login_attempts WHERE ip=? AND username=?",(ip,username)).fetchone()
        if attempt and attempt["locked_until"] and attempt["locked_until"] > stamp:
            raise HTTPException(429,"محاولات كثيرة. حاول مجدداً بعد 15 دقيقة")
        u=c.execute("SELECT * FROM users WHERE username=?",(username,)).fetchone()
        if not u or not u["active"] or not verify_pw(password,u["password"]):
            failed=True
            if attempt and attempt["window_start"] > (datetime.now()-timedelta(minutes=15)).isoformat(timespec="seconds"):
                count=int(attempt["attempts"])+1
                window=attempt["window_start"]
            else:
                count=1
                window=stamp
            locked=(datetime.now()+timedelta(minutes=15)).isoformat(timespec="seconds") if count>=8 else ""
            c.execute("INSERT INTO login_attempts(ip,username,attempts,window_start,locked_until) VALUES(?,?,?,?,?) ON CONFLICT(ip,username) DO UPDATE SET attempts=excluded.attempts,window_start=excluded.window_start,locked_until=excluded.locked_until",(ip,username,count,window,locked))
        else:
            c.execute("DELETE FROM login_attempts WHERE ip=? AND username=?",(ip,username))
    if failed:
        raise HTTPException(401,"اسم المستخدم أو كلمة المرور غير صحيحة")
    token=signer.dumps({"uid":u["id"],"sv":u["session_version"]})
    response.set_cookie("sultan_session",token,httponly=True,samesite="lax",secure=(os.getenv("SULTAN_COOKIE_SECURE", "1" if APP_ENV == "production" else "0") == "1"),max_age=60*60*12)
    return {"ok":True}
@app.post("/api/logout")
def logout(response: Response):
    response.delete_cookie("sultan_session"); return {"ok":True}
@app.get("/api/me")
def me(request: Request):
    u=current_user(request)
    return {k:u[k] for k in ("id","username","full_name","role","branch_id")}
@app.post("/api/change-password")
async def change_password(request: Request):
    u=current_user(request); d=await request.json()
    old=str(d.get("old_password","")); new=str(d.get("new_password",""))
    if len(new)<10: raise HTTPException(400,"كلمة المرور الجديدة يجب أن تتكون من 10 أحرف على الأقل")
    with connect() as c:
        row=c.execute("SELECT password FROM users WHERE id=?",(u["id"],)).fetchone()
        if not verify_pw(old,row["password"]): raise HTTPException(400,"كلمة المرور الحالية غير صحيحة")
        c.execute("UPDATE users SET password=?,session_version=session_version+1 WHERE id=?",(hash_pw(new),u["id"]))
        audit(c,u,"تغيير كلمة المرور")
    return {"ok":True}

@app.get("/api/branches")
def branches(request: Request):
    u=current_user(request)
    with connect() as c:
        if u["role"]=="owner": rows=c.execute("SELECT * FROM branches WHERE active=1 ORDER BY id").fetchall()
        else: rows=c.execute("SELECT * FROM branches WHERE id=? AND active=1",(u["branch_id"],)).fetchall()
    return [dict(x) for x in rows]

@app.post("/api/branches")
async def add_branch(request: Request):
    u=current_user(request); require_owner(u); d=await request.json()
    name=str(d.get("name","")).strip()
    if not name: raise HTTPException(400,"اسم الفرع مطلوب")
    with connect() as c:
        try: cur=c.execute("INSERT INTO branches(name) VALUES(?)",(name,))
        except sqlite3.IntegrityError: raise HTTPException(400,"اسم الفرع موجود مسبقاً")
        audit(c,u,"إضافة فرع",name)
        return {"id":cur.lastrowid,"name":name}

@app.get("/api/users")
def users(request: Request):
    u=current_user(request); require_owner(u)
    with connect() as c:
        return [dict(x) for x in c.execute("SELECT id,username,full_name,role,branch_id,active FROM users ORDER BY id")]
@app.post("/api/users")
async def add_user(request: Request):
    u=current_user(request); require_owner(u); d=await request.json()
    username=str(d.get("username","")).strip(); password=str(d.get("password","")); full=str(d.get("full_name","")).strip()
    role=d.get("role","employee"); branch=int(d.get("branch_id") or u["branch_id"])
    if not username or not full or len(password)<10: raise HTTPException(400,"أدخل الاسم واسم المستخدم وكلمة مرور من 10 أحرف على الأقل")
    if role not in ("owner","employee"): raise HTTPException(400,"دور غير صالح")
    with connect() as c:
        if not c.execute("SELECT 1 FROM branches WHERE id=? AND active=1",(branch,)).fetchone():
            raise HTTPException(400,"الفرع المحدد غير موجود أو غير نشط")
        try:
            cur=c.execute("INSERT INTO users(username,password,full_name,role,branch_id,permissions) VALUES(?,?,?,?,?,?)",(username,hash_pw(password),full,role,branch,"[]" if role=="employee" else ""))
        except sqlite3.IntegrityError: raise HTTPException(400,"اسم المستخدم مستخدم أو الفرع غير موجود")
        audit(c,u,"إضافة مستخدم",username)
        return {"id":cur.lastrowid}
@app.patch("/api/users/{uid}/active")
async def user_active(uid:int, request:Request):
    u=current_user(request); require_owner(u); d=await request.json()
    if uid==u["id"]: raise HTTPException(400,"لا يمكن تعطيل حسابك الحالي")
    with connect() as c:
        c.execute("UPDATE users SET active=?,session_version=session_version+1 WHERE id=?",(1 if d.get("active") else 0,uid))
        audit(c,u,"تغيير حالة مستخدم",str(uid))
    return {"ok":True}

@app.patch("/api/users/{uid}/permissions")
async def set_user_permissions(uid: int, request: Request):
    u=current_user(request); require_owner(u); d=await request.json()
    allowed={"products","sales","expenses","debts","repairs","purchases","transfers","cash","inventory","reports","dashboard"}
    requested=d.get("permissions", [])
    if not isinstance(requested,list) or any(x not in allowed for x in requested):
        raise HTTPException(400,"قائمة الصلاحيات غير صالحة")
    with connect() as c:
        target=c.execute("SELECT id,role FROM users WHERE id=?",(uid,)).fetchone()
        if not target: raise HTTPException(404,"المستخدم غير موجود")
        if target["role"]=="owner": raise HTTPException(400,"لا يمكن تعديل صلاحيات حساب مالك من هنا")
        c.execute("UPDATE users SET permissions=? WHERE id=?",(json.dumps(sorted(set(requested))),uid))
        audit(c,u,"تعديل صلاحيات موظف",f"user_id={uid}; permissions={','.join(sorted(set(requested)))}")
    return {"ok":True,"permissions":sorted(set(requested))}

@app.get("/api/users/{uid}/permissions")
def get_user_permissions(uid: int, request: Request):
    u=current_user(request); require_owner(u)
    with connect() as c:
        target=c.execute("SELECT id,role,permissions FROM users WHERE id=?",(uid,)).fetchone()
    if not target: raise HTTPException(404,"المستخدم غير موجود")
    try: permissions=json.loads(target["permissions"] or "[]")
    except Exception: permissions=[]
    return {"permissions":permissions}

@app.get("/api/products")
def products(request:Request):
    u=current_user(request); bid=scope_branch(u)
    with connect() as c:
        if u["role"] == "owner" and bid is None:
            rows=c.execute("""SELECT p.*,COALESCE(SUM(s.quantity),0) quantity
                FROM products p LEFT JOIN stock s ON s.product_id=p.id
                WHERE p.active=1 GROUP BY p.id ORDER BY p.id DESC""").fetchall()
        else:
            branch_id = bid if bid is not None else u["branch_id"]
            rows=c.execute("""SELECT p.*,COALESCE(s.quantity,0) quantity FROM products p
                LEFT JOIN stock s ON s.product_id=p.id AND s.branch_id=?
                WHERE p.active=1 ORDER BY p.id DESC""",(branch_id,)).fetchall()
    return [dict(x) for x in rows]
@app.post("/api/products")
async def add_product(request:Request):
    u=current_user(request); d=await request.json()
    name=str(d.get("name","")).strip()
    if not name: raise HTTPException(400,"اسم المنتج مطلوب")
    bid=scope_branch(u,d.get("branch_id"))
    barcode=str(d.get("barcode","")).strip() or "SLT"+secrets.token_hex(5).upper()
    with connect() as c:
        try:
            cur=c.execute("""INSERT INTO products(name,category,description,barcode,purchase_price,selling_price,min_stock)
            VALUES(?,?,?,?,?,?,?)""",(name,d.get("category","أخرى"),d.get("description",""),barcode,num(d.get("purchase_price",0),"سعر الشراء"),num(d.get("selling_price",0),"سعر البيع"),num(d.get("min_stock",0),"حد المخزون")))
        except sqlite3.IntegrityError: raise HTTPException(400,"الباركود مستخدم من قبل")
        pid=cur.lastrowid
        c.execute("INSERT INTO stock(product_id,branch_id,quantity) VALUES(?,?,?)",(pid,bid or u["branch_id"],num(d.get("quantity",0),"الكمية")))
        audit(c,u,"إضافة منتج",name)
    return {"id":pid,"barcode":barcode}
@app.patch("/api/products/{pid}")
async def update_product(pid:int,request:Request):
    u=current_user(request); d=await request.json()
    with connect() as c:
        p=c.execute("SELECT * FROM products WHERE id=?",(pid,)).fetchone()
        if not p: raise HTTPException(404,"المنتج غير موجود")
        fields=["name","category","description","barcode","purchase_price","selling_price","min_stock"]
        vals=[d.get(k,p[k]) for k in fields]
        vals[3]=str(vals[3] or "").strip() or p["barcode"]
        vals[4]=num(vals[4],"سعر الشراء"); vals[5]=num(vals[5],"سعر البيع"); vals[6]=num(vals[6],"حد المخزون")
        try: c.execute("UPDATE products SET name=?,category=?,description=?,barcode=?,purchase_price=?,selling_price=?,min_stock=? WHERE id=?",(*vals,pid))
        except sqlite3.IntegrityError: raise HTTPException(400,"الباركود مستخدم من قبل")
        if "quantity" in d:
            raise HTTPException(400,"لا تعدّل المخزون من نموذج المنتج؛ استخدم الجرد لتسجيل الكمية والسبب")
        audit(c,u,"تعديل بيانات منتج",str(pid))
    return {"ok":True}
@app.delete("/api/products/{pid}")
def delete_product(pid:int,request:Request):
    u=current_user(request); require_owner(u)
    with connect() as c:
        c.execute("UPDATE products SET active=0 WHERE id=?",(pid,)); audit(c,u,"إيقاف منتج",str(pid))
    return {"ok":True}

@app.post("/api/sales")
async def create_sale(request:Request):
    u=current_user(request); d=await request.json(); bid=scope_branch(u,d.get("branch_id")) or u["branch_id"]
    items=d.get("items") or []
    if not items: raise HTTPException(400,"الفاتورة فارغة")
    discount=num(d.get("discount",0),"الخصم")
    with connect() as c:
        subtotal=0; normalized=[]; requested={}
        for it in items:
            pid=int(it["product_id"]); qty=num(it.get("qty",1),"الكمية")
            if qty<=0: raise HTTPException(400,"الكمية يجب أن تكون أكبر من صفر")
            requested[pid]=requested.get(pid,0)+qty
        for pid,qty in requested.items():
            p=c.execute("SELECT * FROM products WHERE id=? AND active=1",(pid,)).fetchone()
            s=c.execute("SELECT quantity FROM stock WHERE product_id=? AND branch_id=?",(pid,bid)).fetchone()
            if not p or not s or s["quantity"]<qty: raise HTTPException(400,f"المخزون غير كافٍ للمنتج: {p['name'] if p else pid}")
            line=qty*p["selling_price"]; subtotal+=line; normalized.append((p,qty,line))
        if discount>subtotal: raise HTTPException(400,"الخصم أكبر من المجموع")
        total=subtotal-discount; paid=num(d.get("paid",total),"المبلغ المدفوع")
        if paid>total: raise HTTPException(400,"المبلغ المدفوع أكبر من الإجمالي")
        inv="SLT-"+datetime.now().strftime("%y%m%d%H%M%S")+"-"+secrets.token_hex(2).upper()
        cur=c.execute("INSERT INTO sales(invoice_no,branch_id,user_id,subtotal,discount,total,paid,payment_method,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
                      (inv,bid,u["id"],subtotal,discount,total,paid,d.get("payment_method","نقدي"),now()))
        sid=cur.lastrowid
        for p,qty,line in normalized:
            c.execute("INSERT INTO sale_items(sale_id,product_id,name,qty,unit_price,line_total,unit_cost) VALUES(?,?,?,?,?,?,?)",(sid,p["id"],p["name"],qty,p["selling_price"],line,p["purchase_price"]))
            c.execute("UPDATE stock SET quantity=quantity-? WHERE product_id=? AND branch_id=?",(qty,p["id"],bid))
            c.execute("INSERT INTO stock_movements(product_id,branch_id,user_id,kind,quantity,reference,created_at) VALUES(?,?,?,?,?,?,?)",(p["id"],bid,u["id"],"sale",-qty,inv,now()))
        audit(c,u,"إنشاء فاتورة",inv)
    return {"id":sid,"invoice_no":inv,"subtotal":subtotal,"discount":discount,"total":total,"paid":paid,"remaining":total-paid}
@app.get("/api/sales")
def sales(request:Request):
    u=current_user(request); bid=scope_branch(u)
    with connect() as c:
        rows=c.execute("""SELECT s.*,b.name branch_name,u.full_name FROM sales s JOIN branches b ON b.id=s.branch_id JOIN users u ON u.id=s.user_id
        WHERE (? IS NULL OR s.branch_id=?) ORDER BY s.id DESC LIMIT 200""",(bid,bid)).fetchall()
    return [dict(x) for x in rows]
@app.get("/api/sales/{sid}")
def sale_detail(sid:int,request:Request):
    u=current_user(request)
    with connect() as c:
        s=c.execute("SELECT * FROM sales WHERE id=?",(sid,)).fetchone()
        if not s: raise HTTPException(404,"الفاتورة غير موجودة")
        scope_branch(u,s["branch_id"])
        items=c.execute("SELECT * FROM sale_items WHERE sale_id=?",(sid,)).fetchall()
    return {"sale":dict(s),"items":[dict(x) for x in items]}

@app.get("/api/expenses")
def expenses(request:Request):
    u=current_user(request); bid=scope_branch(u)
    with connect() as c:
        return [dict(x) for x in c.execute("SELECT e.*,b.name branch_name FROM expenses e JOIN branches b ON b.id=e.branch_id WHERE (? IS NULL OR e.branch_id=?) ORDER BY e.id DESC LIMIT 300",(bid,bid))]
@app.post("/api/expenses")
async def add_expense(request:Request):
    u=current_user(request); d=await request.json(); bid=scope_branch(u,d.get("branch_id")) or u["branch_id"]
    amount=num(d.get("amount"),"المبلغ")
    with connect() as c:
        cur=c.execute("INSERT INTO expenses(branch_id,user_id,title,category,amount,note,created_at) VALUES(?,?,?,?,?,?,?)",(bid,u["id"],str(d.get("title","")).strip(),d.get("category","أخرى"),amount,d.get("note",""),now()))
        audit(c,u,"إضافة مصروف",str(d.get("title","")))
        return {"id":cur.lastrowid}

@app.get("/api/debts")
def debts(request:Request):
    u=current_user(request); bid=scope_branch(u)
    with connect() as c:
        rows=c.execute("SELECT * FROM debts WHERE (? IS NULL OR branch_id=?) ORDER BY id DESC",(bid,bid)).fetchall()
    out=[]
    for r in rows:
        x=dict(r); x["remaining"]=round(x["original"]-x["paid"],2); out.append(x)
    return out
@app.post("/api/debts")
async def add_debt(request:Request):
    u=current_user(request); d=await request.json(); bid=scope_branch(u,d.get("branch_id")) or u["branch_id"]
    original=num(d.get("original"),"الدين")
    with connect() as c:
        cur=c.execute("INSERT INTO debts(branch_id,customer,phone,original,due_date,note,created_at) VALUES(?,?,?,?,?,?,?)",(bid,str(d.get("customer","")).strip(),d.get("phone",""),original,d.get("due_date",""),d.get("note",""),now()))
        audit(c,u,"إضافة دين",str(d.get("customer","")))
        return {"id":cur.lastrowid}
@app.post("/api/debts/{did}/payments")
async def debt_payment(did:int,request:Request):
    u=current_user(request); d=await request.json(); amount=num(d.get("amount"),"الدفعة")
    with connect() as c:
        debt=c.execute("SELECT * FROM debts WHERE id=?",(did,)).fetchone()
        if not debt: raise HTTPException(404,"الدين غير موجود")
        scope_branch(u,debt["branch_id"])
        remaining=debt["original"]-debt["paid"]
        if amount<=0 or amount>remaining: raise HTTPException(400,"قيمة الدفعة غير صالحة")
        c.execute("UPDATE debts SET paid=paid+? WHERE id=?",(amount,did))
        c.execute("INSERT INTO debt_payments(debt_id,amount,user_id,created_at) VALUES(?,?,?,?)",(did,amount,u["id"],now()))
        audit(c,u,"دفعة دين",str(did))
    return {"ok":True}

@app.get("/api/repairs")
def repairs(request:Request):
    u=current_user(request); bid=scope_branch(u)
    with connect() as c:
        return [dict(x) for x in c.execute("SELECT * FROM repairs WHERE (? IS NULL OR branch_id=?) ORDER BY id DESC",(bid,bid))]
@app.post("/api/repairs")
async def add_repair(request:Request):
    u=current_user(request); d=await request.json(); bid=scope_branch(u,d.get("branch_id")) or u["branch_id"]
    with connect() as c:
        cur=c.execute("INSERT INTO repairs(branch_id,customer,phone,item,issue,cost,paid,status,note,created_at,user_id) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
          (bid,str(d.get("customer","")).strip(),d.get("phone",""),str(d.get("item","")).strip(),d.get("issue",""),num(d.get("cost",0),"التكلفة"),num(d.get("paid",0),"المدفوع"),d.get("status","مستلم"),d.get("note",""),now(),u["id"]))
        audit(c,u,"إضافة إصلاح",str(d.get("item","")))
        return {"id":cur.lastrowid}
@app.patch("/api/repairs/{rid}")
async def update_repair(rid:int,request:Request):
    u=current_user(request); d=await request.json()
    with connect() as c:
        r=c.execute("SELECT * FROM repairs WHERE id=?",(rid,)).fetchone()
        if not r: raise HTTPException(404,"العملية غير موجودة")
        scope_branch(u,r["branch_id"])
        c.execute("UPDATE repairs SET status=?,note=? WHERE id=?",(d.get("status",r["status"]),d.get("note",r["note"]),rid))
        audit(c,u,"تحديث حالة إصلاح",str(rid))
    return {"ok":True}

@app.get("/api/dashboard")
def dashboard(request:Request):
    u=current_user(request); bid=scope_branch(u)
    with connect() as c:
        where="(? IS NULL OR branch_id=?)"; args=(bid,bid)
        sales=c.execute(f"SELECT COALESCE(SUM(total),0) v,COUNT(*) n FROM sales WHERE {where}",args).fetchone()
        expenses=c.execute(f"SELECT COALESCE(SUM(amount),0) v FROM expenses WHERE {where}",args).fetchone()
        debts=c.execute(f"SELECT COALESCE(SUM(original-paid),0) v FROM debts WHERE {where}",args).fetchone()
        if u["role"] == "owner" and bid is None:
            stock=c.execute("""SELECT COUNT(*) n FROM products p WHERE p.active=1 AND
                EXISTS (SELECT 1 FROM branches b WHERE b.active=1 AND
                COALESCE((SELECT quantity FROM stock s WHERE s.product_id=p.id AND s.branch_id=b.id),0)<=p.min_stock)""").fetchone()
        else:
            branch_id = bid if bid is not None else u["branch_id"]
            stock=c.execute("SELECT COUNT(*) n FROM products p LEFT JOIN stock s ON s.product_id=p.id AND s.branch_id=? WHERE p.active=1 AND COALESCE(s.quantity,0)<=p.min_stock",(branch_id,)).fetchone()
        return {"sales_total":sales["v"],"sales_count":sales["n"],"expenses_total":expenses["v"],"debts_remaining":debts["v"],"low_stock":stock["n"]}
@app.get("/api/reports")
def reports(request:Request):
    u=current_user(request); bid=scope_branch(u)
    with connect() as c:
        rows=c.execute("""SELECT date(created_at) day, SUM(total) sales, COUNT(*) invoices FROM sales
        WHERE (? IS NULL OR branch_id=?) GROUP BY date(created_at) ORDER BY day DESC LIMIT 30""",(bid,bid)).fetchall()
        return [dict(x) for x in rows]
@app.get("/api/audit")
def audit_log(request:Request):
    u=current_user(request); require_owner(u)
    with connect() as c:
        return [dict(x) for x in c.execute("SELECT a.*,u.username FROM audit a LEFT JOIN users u ON u.id=a.user_id ORDER BY a.id DESC LIMIT 200")]
@app.get("/api/backup")
def backup(request:Request):
    u=current_user(request); require_owner(u)
    # SQLite's online backup API includes committed WAL data consistently.
    dest=ROOT/f"sultan-backup-{datetime.now().strftime('%Y%m%d-%H%M%S')}.db"
    src=sqlite3.connect(DB, timeout=20)
    try:
        target=sqlite3.connect(dest)
        try:
            src.backup(target)
            check=target.execute("PRAGMA quick_check").fetchone()[0]
            if check != "ok":
                raise HTTPException(500, "تعذر التحقق من سلامة النسخة الاحتياطية")
        finally:
            target.close()
    finally:
        src.close()
    return FileResponse(dest,filename=dest.name,media_type="application/octet-stream")

@app.post("/api/backup/restore")
async def restore_backup(request: Request):
    u=current_user(request); require_owner(u)
    raw=await request.body()
    if not raw or len(raw)>100*1024*1024:
        raise HTTPException(400,"ملف النسخة الاحتياطية فارغ أو أكبر من 100 ميغابايت")
    temp=ROOT/f"restore-check-{secrets.token_hex(6)}.db"
    safety=ROOT/f"before-restore-{datetime.now().strftime('%Y%m%d-%H%M%S')}.db"
    try:
        temp.write_bytes(raw)
        check_db=sqlite3.connect(temp)
        try:
            integrity=check_db.execute("PRAGMA integrity_check").fetchone()[0]
            tables={r[0] for r in check_db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            required={"users","branches","products","stock","sales","sale_items"}
            if integrity!="ok" or not required.issubset(tables):
                raise HTTPException(400,"الملف ليس نسخة سليمة من قاعدة بيانات SULTAN")
        finally:
            check_db.close()
        # Keep a recoverable copy of the current database before replacing it.
        current=sqlite3.connect(DB, timeout=20)
        try:
            safe=sqlite3.connect(safety)
            try: current.backup(safe)
            finally: safe.close()
        finally:
            current.close()
        with connect() as old_db:
            old_db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        for sidecar in (Path(str(DB)+"-wal"), Path(str(DB)+"-shm")):
            if sidecar.exists():
                sidecar.unlink()
        os.replace(temp,DB)
        # Apply forward-compatible schema migrations before invalidating restored sessions.
        init_db()
        with connect() as c:
            c.execute("UPDATE users SET session_version=session_version+1")
        audit_user={"id":u["id"],"branch_id":u["branch_id"]}
        with connect() as c:
            audit(c,audit_user,"استعادة نسخة احتياطية",safety.name)
        return {"ok":True,"message":"تمت الاستعادة. النسخة السابقة محفوظة على الخادم باسم "+safety.name}
    finally:
        if temp.exists(): temp.unlink()

# Extended operational modules: purchases, returns, inter-branch transfers and cash closing.
@app.post("/api/purchases")
async def create_purchase(request: Request):
    u=current_user(request); d=await request.json(); bid=scope_branch(u,d.get("branch_id")) or u["branch_id"]
    items=d.get("items") or []
    if not items: raise HTTPException(400,"فاتورة الشراء فارغة")
    ref="BUY-"+datetime.now().strftime("%y%m%d%H%M%S")+"-"+secrets.token_hex(2).upper()
    with connect() as c:
        normalized=[]; total=0
        for it in items:
            pid=int(it["product_id"]); qty=num(it.get("qty"),"الكمية"); cost=num(it.get("unit_cost"),"تكلفة الوحدة")
            if qty<=0: raise HTTPException(400,"الكمية يجب أن تكون أكبر من صفر")
            p=c.execute("SELECT id FROM products WHERE id=? AND active=1",(pid,)).fetchone()
            if not p: raise HTTPException(404,"منتج غير موجود")
            normalized.append((pid,qty,cost)); total+=qty*cost
        cur=c.execute("INSERT INTO purchases(reference,branch_id,user_id,total,created_at) VALUES(?,?,?,?,?)",(ref,bid,u["id"],total,now()))
        for pid,qty,cost in normalized:
            c.execute("INSERT INTO purchase_items(purchase_id,product_id,qty,unit_cost) VALUES(?,?,?,?)",(cur.lastrowid,pid,qty,cost))
            c.execute("INSERT INTO stock(product_id,branch_id,quantity) VALUES(?,?,?) ON CONFLICT(product_id,branch_id) DO UPDATE SET quantity=quantity+excluded.quantity",(pid,bid,qty))
            c.execute("INSERT INTO stock_movements(product_id,branch_id,user_id,kind,quantity,reference,created_at) VALUES(?,?,?,?,?,?,?)",(pid,bid,u["id"],"purchase",qty,ref,now()))
        audit(c,u,"تسجيل مشتريات",ref)
    return {"id":cur.lastrowid,"reference":ref,"total":round(total,2)}

@app.get("/api/purchases")
def list_purchases(request: Request):
    u=current_user(request); bid=scope_branch(u)
    with connect() as c:
        return [dict(r) for r in c.execute("SELECT p.*,b.name branch_name,u.full_name FROM purchases p JOIN branches b ON b.id=p.branch_id JOIN users u ON u.id=p.user_id WHERE (? IS NULL OR p.branch_id=?) ORDER BY p.id DESC LIMIT 200",(bid,bid))]

@app.post("/api/sales/{sid}/returns")
async def create_return(sid:int,request:Request):
    u=current_user(request); d=await request.json(); item_id=int(d.get("sale_item_id",0)); qty=num(d.get("qty"),"كمية الإرجاع")
    if qty<=0: raise HTTPException(400,"كمية الإرجاع يجب أن تكون أكبر من صفر")
    method=str(d.get("refund_method","نقدي")); reason=str(d.get("reason",""))
    if method not in ("نقدي", "رصيد"):
        raise HTTPException(400,"طريقة رد المبلغ غير صالحة")
    with connect() as c:
        sale=c.execute("SELECT * FROM sales WHERE id=?",(sid,)).fetchone()
        if not sale: raise HTTPException(404,"الفاتورة غير موجودة")
        scope_branch(u,sale["branch_id"])
        item=c.execute("SELECT * FROM sale_items WHERE id=? AND sale_id=?",(item_id,sid)).fetchone()
        if not item: raise HTTPException(404,"المنتج غير موجود في هذه الفاتورة")
        already=c.execute("SELECT COALESCE(SUM(qty),0) q FROM returns WHERE sale_item_id=?",(item_id,)).fetchone()["q"]
        if qty>item["qty"]-already: raise HTTPException(400,"كمية الإرجاع تتجاوز الكمية المتبقية")
        sale_discount_ratio=(float(sale["discount"])/float(sale["subtotal"])) if float(sale["subtotal"]) > 0 else 0.0
        amount=round(qty*item["unit_price"]*(1-sale_discount_ratio),2)
        cur=c.execute("INSERT INTO returns(sale_id,sale_item_id,branch_id,user_id,qty,amount,refund_method,reason,created_at) VALUES(?,?,?,?,?,?,?,?,?)",(sid,item_id,sale["branch_id"],u["id"],qty,amount,method,reason,now()))
        c.execute("INSERT INTO stock(product_id,branch_id,quantity) VALUES(?,?,?) ON CONFLICT(product_id,branch_id) DO UPDATE SET quantity=quantity+excluded.quantity",(item["product_id"],sale["branch_id"],qty))
        c.execute("INSERT INTO stock_movements(product_id,branch_id,user_id,kind,quantity,reference,note,created_at) VALUES(?,?,?,?,?,?,?,?)",(item["product_id"],sale["branch_id"],u["id"],"return",qty,sale["invoice_no"],reason,now()))
        audit(c,u,"إرجاع مبيعات",f"{sale['invoice_no']} / {qty}")
    return {"id":cur.lastrowid,"refund_amount":amount}

@app.get("/api/sales/{sid}/returnable-items")
def returnable_items(sid:int,request:Request):
    u=current_user(request)
    with connect() as c:
        sale=c.execute("SELECT * FROM sales WHERE id=?",(sid,)).fetchone()
        if not sale: raise HTTPException(404,"الفاتورة غير موجودة")
        scope_branch(u,sale["branch_id"])
        rows=c.execute("SELECT i.*,i.qty-COALESCE((SELECT SUM(r.qty) FROM returns r WHERE r.sale_item_id=i.id),0) returnable FROM sale_items i WHERE i.sale_id=?",(sid,)).fetchall()
        return [dict(x) for x in rows]

@app.post("/api/transfers")
async def request_transfer(request:Request):
    u=current_user(request); d=await request.json(); src=int(d.get("from_branch",u["branch_id"])); dst=int(d.get("to_branch",0)); pid=int(d.get("product_id",0)); qty=num(d.get("qty"),"الكمية")
    if qty<=0 or src==dst: raise HTTPException(400,"بيانات التحويل غير صالحة")
    scope_branch(u,src)
    with connect() as c:
        if not c.execute("SELECT id FROM branches WHERE id=? AND active=1",(dst,)).fetchone(): raise HTTPException(404,"الفرع المستلم غير موجود")
        st=c.execute("SELECT quantity FROM stock WHERE product_id=? AND branch_id=?",(pid,src)).fetchone()
        if not st or st["quantity"]<qty: raise HTTPException(400,"المخزون غير كافٍ")
        cur=c.execute("INSERT INTO transfers(product_id,from_branch,to_branch,qty,requested_by,note,created_at) VALUES(?,?,?,?,?,?,?)",(pid,src,dst,qty,u["id"],str(d.get("note","")),now()))
        audit(c,u,"طلب تحويل مخزون",str(cur.lastrowid))
    return {"id":cur.lastrowid,"status":"pending"}

@app.get("/api/transfers")
def list_transfers(request:Request):
    u=current_user(request)
    with connect() as c:
        if u["role"]=="owner": rows=c.execute("SELECT t.*,p.name product_name,b1.name from_name,b2.name to_name FROM transfers t JOIN products p ON p.id=t.product_id JOIN branches b1 ON b1.id=t.from_branch JOIN branches b2 ON b2.id=t.to_branch ORDER BY t.id DESC").fetchall()
        else: rows=c.execute("SELECT t.*,p.name product_name,b1.name from_name,b2.name to_name FROM transfers t JOIN products p ON p.id=t.product_id JOIN branches b1 ON b1.id=t.from_branch JOIN branches b2 ON b2.id=t.to_branch WHERE t.from_branch=? OR t.to_branch=? ORDER BY t.id DESC",(u["branch_id"],u["branch_id"])).fetchall()
        return [dict(r) for r in rows]

@app.post("/api/transfers/{tid}/decision")
async def decide_transfer(tid:int,request:Request):
    u=current_user(request); require_owner(u); d=await request.json(); approve=d.get("approve")
    if not isinstance(approve, bool): raise HTTPException(400,"قرار التحويل يجب أن يكون true أو false")
    with connect() as c:
        t=c.execute("SELECT * FROM transfers WHERE id=?",(tid,)).fetchone()
        if not t: raise HTTPException(404,"طلب التحويل غير موجود")
        if t["status"]!="pending": raise HTTPException(409,"تمت معالجة هذا الطلب سابقاً")
        if approve:
            src=c.execute("SELECT quantity FROM stock WHERE product_id=? AND branch_id=?",(t["product_id"],t["from_branch"])).fetchone()
            if not src or src["quantity"]<t["qty"]: raise HTTPException(400,"المخزون لم يعد كافياً")
            c.execute("UPDATE stock SET quantity=quantity-? WHERE product_id=? AND branch_id=?",(t["qty"],t["product_id"],t["from_branch"]))
            c.execute("INSERT INTO stock(product_id,branch_id,quantity) VALUES(?,?,?) ON CONFLICT(product_id,branch_id) DO UPDATE SET quantity=quantity+excluded.quantity",(t["product_id"],t["to_branch"],t["qty"]))
            for branch,kind,q in [(t["from_branch"],"transfer_out",-t["qty"]),(t["to_branch"],"transfer_in",t["qty"])]:
                c.execute("INSERT INTO stock_movements(product_id,branch_id,user_id,kind,quantity,reference,created_at) VALUES(?,?,?,?,?,?,?)",(t["product_id"],branch,u["id"],kind,q,f"TR-{tid}",now()))
            status="approved"
        else: status="rejected"
        c.execute("UPDATE transfers SET status=?,approved_by=?,decided_at=? WHERE id=?",(status,u["id"],now(),tid))
        audit(c,u,"قرار تحويل مخزون",f"{tid}: {status}")
    return {"ok":True,"status":status}

@app.get("/api/stock-movements")
def stock_movements(request:Request):
    u=current_user(request); bid=scope_branch(u)
    with connect() as c:
        return [dict(r) for r in c.execute("SELECT m.*,p.name product_name,b.name branch_name,u.username FROM stock_movements m JOIN products p ON p.id=m.product_id JOIN branches b ON b.id=m.branch_id JOIN users u ON u.id=m.user_id WHERE (? IS NULL OR m.branch_id=?) ORDER BY m.id DESC LIMIT 500",(bid,bid))]

@app.post("/api/cash-closings")
async def create_cash_closing(request:Request):
    u=current_user(request); d=await request.json(); bid=scope_branch(u,d.get("branch_id")) or u["branch_id"]
    day=str(d.get("business_date") or date.today().isoformat()); actual=num(d.get("cash_actual"),"النقد الفعلي")
    with connect() as c:
        sales=c.execute("SELECT COALESCE(SUM(paid),0) cash FROM sales WHERE branch_id=? AND date(created_at)=? AND payment_method='نقدي'",(bid,day)).fetchone()["cash"]
        expenses=c.execute("SELECT COALESCE(SUM(amount),0) v FROM expenses WHERE branch_id=? AND date(created_at)=?",(bid,day)).fetchone()["v"]
        returns=c.execute("SELECT COALESCE(SUM(amount),0) v FROM returns WHERE branch_id=? AND date(created_at)=? AND refund_method='نقدي'",(bid,day)).fetchone()["v"]
        other=c.execute("SELECT COALESCE(SUM(paid),0) v FROM sales WHERE branch_id=? AND date(created_at)=? AND payment_method!='نقدي'",(bid,day)).fetchone()["v"]
        expected=round(sales-expenses-returns,2); diff=round(actual-expected,2)
        try:
            cur=c.execute("INSERT INTO cash_closings(branch_id,user_id,business_date,cash_expected,cash_actual,other_payments,expenses,returns,difference,note,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)",(bid,u["id"],day,expected,actual,other,expenses,returns,diff,str(d.get("note","")),now()))
        except sqlite3.IntegrityError: raise HTTPException(409,"تم إغلاق الصندوق لهذا الفرع واليوم مسبقاً")
        audit(c,u,"إغلاق الصندوق",f"{day}: {diff}")
    return {"id":cur.lastrowid,"cash_expected":expected,"cash_actual":actual,"difference":diff,"other_payments":other,"expenses":expenses,"returns":returns}

@app.get("/api/cash-closings")
def list_cash_closings(request:Request):
    u=current_user(request); bid=scope_branch(u)
    with connect() as c:
        return [dict(r) for r in c.execute("SELECT * FROM cash_closings WHERE (? IS NULL OR branch_id=?) ORDER BY business_date DESC LIMIT 90",(bid,bid))]


@app.get("/api/reports/summary")
def report_summary(request: Request, start: str = "", end: str = "", branch_id: Optional[int] = None):
    u=current_user(request); bid=scope_branch(u,branch_id)
    if start and end and start > end: raise HTTPException(400,"تاريخ البداية يجب ألا يتجاوز تاريخ النهاية")
    clauses=[]; args=[]
    if bid is not None: clauses.append("s.branch_id=?"); args.append(bid)
    if start: clauses.append("date(s.created_at)>=date(?)"); args.append(start)
    if end: clauses.append("date(s.created_at)<=date(?)"); args.append(end)
    where=(" WHERE "+" AND ".join(clauses)) if clauses else ""
    with connect() as c:
        sales=c.execute("SELECT COALESCE(SUM(total),0) v,COALESCE(SUM(discount),0) discount,COUNT(*) n FROM sales s"+where,args).fetchone()
        rc=[]; ra=[]
        if bid is not None: rc.append("r.branch_id=?"); ra.append(bid)
        if start: rc.append("date(r.created_at)>=date(?)"); ra.append(start)
        if end: rc.append("date(r.created_at)<=date(?)"); ra.append(end)
        rw=(" WHERE "+" AND ".join(rc)) if rc else ""
        returned=c.execute("SELECT COALESCE(SUM(amount),0) v,COALESCE(SUM(qty),0) q FROM returns r"+rw,ra).fetchone()
        cogs=c.execute("SELECT COALESCE(SUM(i.qty*i.unit_cost),0) v FROM sale_items i JOIN sales s ON s.id=i.sale_id"+where,args).fetchone()["v"]
        return_cost=c.execute("SELECT COALESCE(SUM(r.qty*i.unit_cost),0) v FROM returns r JOIN sale_items i ON i.id=r.sale_item_id"+rw,ra).fetchone()["v"]
        ec=[]; ea=[]
        if bid is not None: ec.append("branch_id=?"); ea.append(bid)
        if start: ec.append("date(created_at)>=date(?)"); ea.append(start)
        if end: ec.append("date(created_at)<=date(?)"); ea.append(end)
        ew=(" WHERE "+" AND ".join(ec)) if ec else ""
        expenses=c.execute("SELECT COALESCE(SUM(amount),0) v FROM expenses"+ew,ea).fetchone()["v"]
        net_sales=round(float(sales["v"])-float(returned["v"]),2); net_cogs=round(float(cogs)-float(return_cost),2)
        gross=round(net_sales-net_cogs,2); net=round(gross-float(expenses),2)
        return {"sales_gross":round(float(sales["v"]),2),"returns":round(float(returned["v"]),2),"net_sales":net_sales,"cogs":net_cogs,"gross_profit":gross,"expenses":round(float(expenses),2),"net_profit":net,"discounts":round(float(sales["discount"]),2),"invoice_count":int(sales["n"]),"returned_quantity":float(returned["q"]),"cost_method":"تكلفة الشراء المسجلة وقت البيع؛ السجلات القديمة تستخدم سعر الشراء الحالي كقيمة تقديرية عند الترحيل"}

@app.get("/api/reports/export.csv")
def export_report_csv(request: Request, start: str = "", end: str = "", branch_id: Optional[int] = None):
    data=report_summary(request,start,end,branch_id); out=io.StringIO(); w=csv.writer(out); w.writerow(["المؤشر","القيمة"])
    labels={"sales_gross":"إجمالي المبيعات قبل المرتجعات","returns":"المرتجعات","net_sales":"صافي المبيعات","cogs":"تكلفة البضاعة المباعة","gross_profit":"مجمل الربح","expenses":"المصاريف","net_profit":"صافي الربح التشغيلي","discounts":"الخصومات","invoice_count":"عدد الفواتير","returned_quantity":"كمية المرتجعات","cost_method":"منهج التكلفة وملاحظة البيانات القديمة"}
    for k,v in data.items(): w.writerow([labels.get(k,k),v])
    from fastapi.responses import StreamingResponse
    return StreamingResponse(iter(["\ufeff"+out.getvalue()]),media_type="text/csv; charset=utf-8",headers={"Content-Disposition":"attachment; filename=sultan-financial-report.csv"})

@app.get("/api/reports/export.xlsx")
def export_report_xlsx(request: Request, start: str = "", end: str = "", branch_id: Optional[int] = None):
    """Export a scoped financial workbook with summary and transaction sheets."""
    from openpyxl import Workbook
    from openpyxl.styles import Font, PatternFill, Alignment
    from openpyxl.utils import get_column_letter
    from fastapi.responses import StreamingResponse

    u=current_user(request); bid=scope_branch(u,branch_id)
    if start and end and start > end: raise HTTPException(400,"تاريخ البداية يجب ألا يتجاوز تاريخ النهاية")
    summary=report_summary(request,start,end,branch_id)
    wb=Workbook(); ws=wb.active; ws.title="Financial Summary"
    ws.append(["SULTAN SHOP MANAGEMENT", "Financial report"])
    ws.append(["Start date", start or "All"]); ws.append(["End date", end or "All"])
    ws.append(["Metric", "Value"])
    labels={"sales_gross":"Gross sales","returns":"Returns","net_sales":"Net sales","cogs":"Cost of goods sold","gross_profit":"Gross profit","expenses":"Expenses","net_profit":"Operating net profit","discounts":"Discounts","invoice_count":"Invoice count","returned_quantity":"Returned quantity","cost_method":"Cost method"}
    for key,value in summary.items(): ws.append([labels.get(key,key),value])

    sales_ws=wb.create_sheet("Sales")
    sales_ws.append(["Invoice", "Date", "Branch ID", "Subtotal", "Discount", "Total", "Paid", "Payment method"])
    exp_ws=wb.create_sheet("Expenses")
    exp_ws.append(["Date", "Branch ID", "Title", "Category", "Amount", "Note"])
    stock_ws=wb.create_sheet("Stock")
    stock_ws.append(["Product ID", "Product", "Barcode", "Branch ID", "Branch", "Quantity", "Minimum stock"])
    with connect() as c:
        clauses=[]; args=[]
        if bid is not None: clauses.append("branch_id=?"); args.append(bid)
        if start: clauses.append("date(created_at)>=date(?)"); args.append(start)
        if end: clauses.append("date(created_at)<=date(?)"); args.append(end)
        where=(" WHERE "+" AND ".join(clauses)) if clauses else ""
        for r in c.execute("SELECT invoice_no,created_at,branch_id,subtotal,discount,total,paid,payment_method FROM sales"+where+" ORDER BY created_at",args): sales_ws.append(list(r))
        for r in c.execute("SELECT created_at,branch_id,title,category,amount,note FROM expenses"+where+" ORDER BY created_at",args): exp_ws.append(list(r))
        stock_args=[]; stock_where=" WHERE p.active=1 AND b.active=1"
        if bid is not None: stock_where+=" AND b.id=?"; stock_args.append(bid)
        for r in c.execute("SELECT p.id,p.name,p.barcode,b.id,b.name,COALESCE(st.quantity,0),p.min_stock FROM products p CROSS JOIN branches b LEFT JOIN stock st ON st.product_id=p.id AND st.branch_id=b.id"+stock_where+" ORDER BY b.id,p.name",stock_args): stock_ws.append(list(r))
    for sheet in wb.worksheets:
        sheet.freeze_panes="A5" if sheet.title=="Financial Summary" else "A2"
        sheet.auto_filter.ref=sheet.dimensions
        for cell in sheet[1]:
            cell.font=Font(bold=True,color="FFFFFF")
            cell.fill=PatternFill("solid",fgColor="3B1E54")
            cell.alignment=Alignment(horizontal="center")
        for col in sheet.columns:
            letter=get_column_letter(col[0].column)
            width=min(42,max(12,max((len(str(x.value or "")) for x in col),default=10)+2))
            sheet.column_dimensions[letter].width=width
    out=io.BytesIO(); wb.save(out); out.seek(0)
    return StreamingResponse(out,media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",headers={"Content-Disposition":"attachment; filename=sultan-management-report.xlsx"})

@app.post("/api/stocktake/adjust")
async def stocktake_adjust(request: Request):
    u=current_user(request); require_owner(u); d=await request.json(); pid=int(d.get("product_id",0)); bid=int(d.get("branch_id",0)); actual=num(d.get("actual_quantity"),"كمية الجرد"); reason=str(d.get("reason","")).strip()
    if not reason: raise HTTPException(400,"سبب تعديل الجرد مطلوب")
    scope_branch(u, bid)
    with connect() as c:
        p=c.execute("SELECT id,name FROM products WHERE id=? AND active=1",(pid,)).fetchone(); b=c.execute("SELECT id FROM branches WHERE id=? AND active=1",(bid,)).fetchone()
        if not p or not b: raise HTTPException(404,"المنتج أو الفرع غير موجود")
        old=c.execute("SELECT quantity FROM stock WHERE product_id=? AND branch_id=?",(pid,bid)).fetchone(); before=float(old["quantity"]) if old else 0.0; delta=round(actual-before,4)
        c.execute("INSERT INTO stock(product_id,branch_id,quantity) VALUES(?,?,?) ON CONFLICT(product_id,branch_id) DO UPDATE SET quantity=excluded.quantity",(pid,bid,actual))
        c.execute("INSERT INTO stock_movements(product_id,branch_id,user_id,kind,quantity,reference,note,created_at) VALUES(?,?,?,?,?,?,?,?)",(pid,bid,u["id"],"stocktake",delta,"STOCKTAKE",f"{reason} | قبل: {before} | بعد: {actual}",now()))
        audit(c,u,"تسوية جرد مخزون",f"{p['name']} / الفرع {bid} / {before} -> {actual} / {reason}")
    return {"ok":True,"before":before,"actual":actual,"difference":delta}

@app.get("/api/notifications")
def notifications(request: Request):
    u=current_user(request); bid=scope_branch(u)
    with connect() as c:
        if u["role"] == "owner" and bid is None:
            low=c.execute("""SELECT p.id product_id,p.name, b.id branch_id,b.name branch_name,
                    COALESCE(s.quantity,0) quantity,p.min_stock
                FROM products p CROSS JOIN branches b
                LEFT JOIN stock s ON s.product_id=p.id AND s.branch_id=b.id
                WHERE p.active=1 AND b.active=1 AND COALESCE(s.quantity,0)<=p.min_stock
                ORDER BY b.id,p.name LIMIT 500""").fetchall()
        else:
            branch_id = bid if bid is not None else u["branch_id"]
            low=c.execute("""SELECT p.id product_id,p.name,? branch_id,b.name branch_name,
                    COALESCE(s.quantity,0) quantity,p.min_stock
                FROM products p JOIN branches b ON b.id=?
                LEFT JOIN stock s ON s.product_id=p.id AND s.branch_id=b.id
                WHERE p.active=1 AND b.active=1 AND COALESCE(s.quantity,0)<=p.min_stock
                ORDER BY p.name LIMIT 100""",(branch_id,branch_id)).fetchall()
        debts=c.execute("SELECT id,customer,original-paid remaining,due_date FROM debts WHERE (? IS NULL OR branch_id=?) AND due_date<>'' AND date(due_date)<=date('now') AND original>paid ORDER BY due_date LIMIT 100",(bid,bid)).fetchall()
        repairs=c.execute("SELECT id,customer,item,status FROM repairs WHERE (? IS NULL OR branch_id=?) AND status='جاهز' ORDER BY id DESC LIMIT 100",(bid,bid)).fetchall()
        pending=[dict(x) for x in c.execute("SELECT id,product_id,from_branch,to_branch,qty FROM transfers WHERE status='pending' ORDER BY id DESC LIMIT 100")] if u["role"]=="owner" else []
    return {"low_stock":[dict(x) for x in low],"overdue_debts":[dict(x) for x in debts],"ready_repairs":[dict(x) for x in repairs],"pending_transfers":pending}


@app.post("/api/zakat/calculate")
async def calculate_zakat(request: Request):
    u=current_user(request); require_owner(u)
    d=await request.json()
    cash=num(d.get("cash",0),"النقد")
    bank=num(d.get("bank",0),"أرصدة البنوك")
    inventory=num(d.get("inventory",0),"قيمة البضائع")
    receivables=num(d.get("receivables",0),"الديون المرجوة")
    liabilities=num(d.get("liabilities",0),"الالتزامات")
    nisab=num(d.get("nisab",0),"قيمة النصاب")
    for label,value in [("النقد",cash),("أرصدة البنوك",bank),("قيمة البضائع",inventory),("الديون المرجوة",receivables),("الالتزامات",liabilities),("قيمة النصاب",nisab)]:
        if value < 0: raise HTTPException(400,f"{label}: لا يمكن إدخال قيمة سالبة")
    method=str(d.get("liability_method","exclude"))
    if method not in ("exclude","deduct"): raise HTTPException(400,"طريقة احتساب الالتزامات غير صحيحة")
    hawl=bool(d.get("hawl_completed",False))
    gross=round(cash+bank+inventory+receivables,2)
    deducted=liabilities if method=="deduct" else 0.0
    net=round(max(0,gross-deducted),2)
    eligible=bool(hawl and nisab>0 and net>=nisab)
    due=round(net*0.025,2) if eligible else 0.0
    with connect() as c:
        audit(c,u,"حساب تقديري للزكاة",f"الصافي: {net} / النصاب: {nisab} / مستحق: {eligible} / طريقة الالتزامات: {method}")
    return {"gross_assets":gross,"deducted_liabilities":round(deducted,2),"net_zakatable_assets":net,"nisab":round(nisab,2),"hawl_completed":hawl,"eligible":eligible,"rate":0.025,"zakat_due":due,"liability_method":method,"disclaimer":"حساب تقديري مبسط وليس فتوى. تختلف تفاصيل تقويم عروض التجارة والديون والالتزامات والنصاب بين أهل العلم والمذاهب؛ راجع عالماً موثوقاً ومحاسباً، وأدخل قيمة النصاب وفق المرجع الذي تتبعه."}
