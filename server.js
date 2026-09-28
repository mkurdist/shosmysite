const express=require('express'),fs=require('fs'),path=require('path'),crypto=require('crypto');
const {SUPABASE_URL:SB,SUPABASE_KEY:KEY,ZARINPAL_MERCHANT:MID,BASE_URL,ZARINPAL_SANDBOX,ADMIN_PASSWORD:PW}=process.env;
const SEC=process.env.ADMIN_SECRET||PW,DB=!!(SB&&KEY);
const app=express();app.disable('x-powered-by');app.use(express.json({limit:'50kb'}));
app.use((q,s,n)=>{s.set({'X-Content-Type-Options':'nosniff','X-Frame-Options':'DENY','Referrer-Policy':'same-origin'});n()});
app.use(express.static(path.join(__dirname,'public'),{maxAge:'1d'}));
const PF=path.join(__dirname,'products.json');
let local=JSON.parse(fs.readFileSync(PF));
const sb=(p,o={})=>fetch(SB+'/rest/v1/'+p,{...o,headers:{apikey:KEY,Authorization:'Bearer '+KEY,'Content-Type':'application/json',Prefer:'return=representation',...o.headers}}).then(r=>r.json());
let cache=null,at=0;
async function products(){
  if(cache&&Date.now()-at<60000)return cache;
  let d=local;
  if(DB){try{const r=await sb('products?select=*&order=id');if(Array.isArray(r)&&r.length)d=r}catch(e){}}
  at=Date.now();return cache=d;
}
const mem=[];
const Z=ZARINPAL_SANDBOX==='1'?'https://sandbox.zarinpal.com':'https://payment.zarinpal.com';
const zp=(ep,b)=>fetch(Z+'/pg/v4/payment/'+ep+'.json',{method:'POST',headers:{'Content-Type':'application/json',Accept:'application/json'},body:JSON.stringify({merchant_id:MID,...b})}).then(r=>r.json());
const getOrder=async id=>DB?(await sb('orders?id=eq.'+encodeURIComponent(id)+'&select=*'))[0]:mem[id-1];
const setOrder=async(id,f)=>{if(DB)await sb('orders?id=eq.'+encodeURIComponent(id),{method:'PATCH',body:JSON.stringify(f)});else if(mem[id-1])Object.assign(mem[id-1],f)};

/* ---------- storefront ---------- */
app.get('/api/products',async(q,s)=>{s.set('Cache-Control','public,max-age=60');s.json(await products())});
app.post('/api/checkout',async(q,s)=>{
  try{
    const {items,name,phone,address}=q.body||{};
    if(!Array.isArray(items)||!items.length||items.length>30||!name||!/^09\d{9}$/.test(phone||'')||!address)return s.status(400).json({error:'اطلاعات ناقص یا نامعتبر است'});
    const P=await products();let total=0;const lines=[];
    for(const i of items){const p=P.find(x=>x.id===i.id);const n=Math.min(Math.max(+i.qty|0,1),10);if(!p)return s.status(400).json({error:'کالا یافت نشد'});total+=p.price*n;lines.push({id:p.id,name:p.name,size:i.size,qty:n,price:p.price})}
    const o={items:lines,total,name:String(name).slice(0,80),phone,address:String(address).slice(0,400),status:'pending'};
    let id;
    if(DB){id=(await sb('orders',{method:'POST',body:JSON.stringify(o)}))[0].id}else{id=mem.push({...o,id:mem.length+1,created_at:new Date().toISOString()})}
    if(!MID)return s.json({url:`/api/verify?order=${id}&demo=1`});
    const r=await zp('request',{amount:total*10,callback_url:(BASE_URL||'')+'/api/verify?order='+id,description:'سفارش '+id,metadata:{mobile:phone}});
    if(r.data&&r.data.code===100){await setOrder(id,{authority:r.data.authority});return s.json({url:Z+'/pg/StartPay/'+r.data.authority})}
    s.status(502).json({error:'خطا در اتصال به درگاه'});
  }catch(e){s.status(500).json({error:'خطای سرور'})}
});
app.get('/api/verify',async(q,s)=>{
  try{
    const {order,Authority,Status,demo}=q.query,o=await getOrder(order);
    if(!o)return s.redirect('/?paid=fail');
    if(!MID&&demo){await setOrder(order,{status:'paid'});return s.redirect('/?paid=demo&order='+order)}
    if(Status!=='OK'||o.status!=='pending'&&o.status!=='failed'){return s.redirect('/?paid=fail&order='+order)}
    const r=await zp('verify',{amount:o.total*10,authority:Authority});
    const ok=r.data&&(r.data.code===100||r.data.code===101);
    await setOrder(order,{status:ok?'paid':'failed',ref_id:ok?String(r.data.ref_id):null});
    s.redirect('/?paid='+(ok?'ok':'fail')+'&order='+order);
  }catch(e){s.redirect('/?paid=fail')}
});
app.get('/health',(q,s)=>s.send('ok'));

/* ---------- admin ---------- */
const sign=e=>crypto.createHmac('sha256',SEC).update(String(e)).digest('hex');
const hash=x=>crypto.createHash('sha256').update(String(x)).digest();
const tokenOk=t=>{if(!t||!SEC)return false;const [e,g]=t.split('.');if(!e||!g||+e<Date.now())return false;const a=Buffer.from(g),b=Buffer.from(sign(e));return a.length===b.length&&crypto.timingSafeEqual(a,b)};
const tries={};
app.post('/api/admin/login',(q,s)=>{
  if(!PW)return s.status(503).json({error:'ADMIN_PASSWORD روی سرور تنظیم نشده است'});
  const ip=q.ip,t=tries[ip]||(tries[ip]={n:0,u:0});
  if(t.n>=5&&Date.now()<t.u)return s.status(429).json({error:'تلاش زیاد. ۱۵ دقیقه بعد دوباره امتحان کنید'});
  if(!crypto.timingSafeEqual(hash(q.body&&q.body.password||''),hash(PW))){if(++t.n>=5)t.u=Date.now()+9e5;return s.status(401).json({error:'رمز اشتباه است'})}
  delete tries[ip];const e=Date.now()+12*36e5;s.json({token:e+'.'+sign(e)});
});
const A=express.Router();
A.use((q,s,n)=>tokenOk((q.headers.authorization||'').slice(7))?n():s.status(401).json({error:'unauthorized'}));
app.use('/api/admin',A);
const GEN=['مردانه','زنانه','بچگانه'],ST=['pending','paid','shipped','delivered','canceled','failed'];
function clean(b){
  const n=String(b.name||'').trim().slice(0,100),price=Math.round(+b.price),sizes=(Array.isArray(b.sizes)?b.sizes:String(b.sizes||'').split(',')).map(Number).filter(x=>x>0&&x<100);
  if(!n||!(price>=0)||!GEN.includes(b.gender)||!String(b.type||'').trim()||!sizes.length)return null;
  return {name:n,price,gender:b.gender,type:String(b.type).trim().slice(0,30),color:/^#[0-9a-f]{6}$/i.test(b.color)?b.color:'#888888',img:/^https?:\/\//.test(b.img||'')?String(b.img).slice(0,500):'',sizes};
}
A.get('/products',async(q,s)=>{cache=null;s.json(await products())});
A.post('/products',async(q,s)=>{
  const p=clean(q.body||{});if(!p)return s.status(400).json({error:'فیلدها را کامل و درست پر کنید'});
  p.id=q.body.id||'p'+Date.now().toString(36);
  if(DB){await sb('products',{method:'POST',headers:{Prefer:'resolution=merge-duplicates,return=representation'},body:JSON.stringify(p)})}
  else{const i=local.findIndex(x=>x.id===p.id);i<0?local.push(p):local[i]=p;try{fs.writeFileSync(PF,JSON.stringify(local))}catch(e){}}
  cache=null;s.json(p);
});
A.delete('/products/:id',async(q,s)=>{
  if(DB)await sb('products?id=eq.'+encodeURIComponent(q.params.id),{method:'DELETE'});
  else{local=local.filter(x=>x.id!==q.params.id);try{fs.writeFileSync(PF,JSON.stringify(local))}catch(e){}}
  cache=null;s.json({ok:1});
});
A.post('/seed',async(q,s)=>{
  if(!DB)return s.status(400).json({error:'Supabase تنظیم نشده است'});
  await sb('products',{method:'POST',headers:{Prefer:'resolution=ignore-duplicates,return=minimal'},body:JSON.stringify(JSON.parse(fs.readFileSync(PF)))});
  cache=null;s.json({ok:1});
});
A.get('/orders',async(q,s)=>{s.json(DB?await sb('orders?select=*&order=id.desc&limit=300'):[...mem].reverse())});
A.patch('/orders/:id',async(q,s)=>{
  if(!ST.includes(q.body&&q.body.status))return s.status(400).json({error:'وضعیت نامعتبر'});
  await setOrder(q.params.id,{status:q.body.status});s.json({ok:1});
});

/* ---------- media library ---------- */
const BUCKET=process.env.SUPABASE_BUCKET||'media',UP=path.join(__dirname,'uploads');
const EXT={'image/jpeg':'jpg','image/png':'png','image/webp':'webp','image/gif':'gif'};
const sbs=(p,o={})=>fetch(SB+'/storage/v1/'+p,{...o,headers:{apikey:KEY,Authorization:'Bearer '+KEY,...o.headers}});
const pub=n=>SB+'/storage/v1/object/public/'+BUCKET+'/'+n,J={'Content-Type':'application/json'};
let bucketOk=false;
async function ensureBucket(){if(bucketOk)return;await sbs('bucket',{method:'POST',headers:J,body:JSON.stringify({id:BUCKET,name:BUCKET,public:true})});bucketOk=true}
app.use('/uploads',express.static(UP,{maxAge:'7d'}));
A.get('/media',async(q,s)=>{
  try{
    if(DB){await ensureBucket();const r=await sbs('object/list/'+BUCKET,{method:'POST',headers:J,body:JSON.stringify({prefix:'',limit:200,sortBy:{column:'created_at',order:'desc'}})}).then(r=>r.json());
      return s.json((Array.isArray(r)?r:[]).filter(f=>f.name&&f.id).map(f=>({name:f.name,url:pub(f.name)})))}
    fs.mkdirSync(UP,{recursive:true});
    s.json(fs.readdirSync(UP).filter(n=>/^[\w.-]+$/.test(n)).sort().reverse().map(n=>({name:n,url:'/uploads/'+n})));
  }catch(e){s.status(500).json({error:'خطا در خواندن رسانه'})}
});
A.post('/media',express.raw({type:Object.keys(EXT),limit:'5mb'}),async(q,s)=>{
  const ct=q.headers['content-type'],ext=EXT[ct];
  if(!ext||!Buffer.isBuffer(q.body)||!q.body.length)return s.status(400).json({error:'فقط تصویر JPG، PNG، WebP یا GIF (حداکثر ۵ مگابایت)'});
  const name=Date.now().toString(36)+crypto.randomBytes(3).toString('hex')+'.'+ext;
  try{
    if(DB){await ensureBucket();const r=await sbs('object/'+BUCKET+'/'+name,{method:'POST',headers:{'Content-Type':ct,'Cache-Control':'max-age=31536000'},body:q.body});
      if(!r.ok)return s.status(502).json({error:'آپلود در Supabase ناموفق بود'});return s.json({name,url:pub(name)})}
    fs.mkdirSync(UP,{recursive:true});fs.writeFileSync(path.join(UP,name),q.body);s.json({name,url:'/uploads/'+name});
  }catch(e){s.status(500).json({error:'خطای آپلود'})}
});
A.delete('/media/:name',async(q,s)=>{
  const n=q.params.name;if(!/^[\w.-]+$/.test(n))return s.status(400).json({error:'نام نامعتبر'});
  try{if(DB)await sbs('object/'+BUCKET,{method:'DELETE',headers:J,body:JSON.stringify({prefixes:[n]})});else fs.rmSync(path.join(UP,n),{force:true});s.json({ok:1})}
  catch(e){s.status(500).json({error:'خطا در حذف'})}
});
app.listen(process.env.PORT||3000);
