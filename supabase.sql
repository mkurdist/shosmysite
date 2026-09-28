create table products(id text primary key,name text,price int,gender text,type text,color text,img text,sizes int[]);
create table orders(id bigserial primary key,items jsonb,total int,name text,phone text,address text,status text default 'pending',authority text,ref_id text,created_at timestamptz default now());
alter table products enable row level security;
create policy "read" on products for select using (true);
alter table orders enable row level security; -- فقط سرور با service_role کلید مینویسد
