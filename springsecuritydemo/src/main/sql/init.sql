create table users(
                      id bigint primary key auto_increment,
                      username varchar(20) unique not null,
                      password varchar(100)
);
-- 密码 123
insert into users values(1,'wjl','123');
-- 密码 123
insert into users values(2,'wjl1','123');
create table role(
                     id bigint primary key auto_increment,
                     name varchar(20)
);insert into role values(1,'管理员');
insert into role values(2,'普通用户');
create table role_user(
                          uid bigint,
                          rid bigint
);
insert into role_user values(1,1);
insert into role_user values(2,2);
create table menu(
                     id bigint primary key auto_increment,
                     name varchar(20),
                     url varchar(100),
                     parentid bigint,
                     permission varchar(20)
);
insert into menu values(1,'系统管理','',0,'menu:system');
insert into menu values(2,'用户管理','',0,'menu:user');
create table role_menu(
                          mid bigint,
                          rid bigint
);
insert into role_menu values(1,1);insert into role_menu values(2,1);
insert into role_menu values(2,2);
