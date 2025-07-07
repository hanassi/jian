/* 2023 주요정보통신기반시설 MySQL */

/* MySQL 버전 확인*/
SELECT version();

/* mysql.user 테이블 가져오기*/
SELECT * FROM mysql.user;

/* D-01 기본 계정의 패스워드, 정등을 변경하여 사용 */
SELECT user,host,plugin,authentication_string FROM mysql.user;

/* D-02 데이터베이스의 불필요 계정을 제거하거나, 잠금설정 후 사용 */
SELECT user,host FROM mysql.user where user!='mysql.infoschema' and user!='mysql.session' and user!='mysql.sys';

/* D-04 데이터베이스 관리자 권한을 꼭 필요한 계정 및 그룹에 대해서만 허용 */
select user, host, Update_priv, Delete_priv, Create_priv, Drop_priv, Grant_priv, Alter_priv, Super_priv, process_priv, file_priv, shutdown_priv, Lock_tables_priv, Execute_priv from mysql.user where user in(SELECT user FROM mysql.user where user!='mysql.infoschema' and user!='mysql.session' and user!='mysql.sys');

/* D-15 일정 횟수의 로그인 실패 시 이에 대한 잠금정책이 설정 */
select user, User_attributes from mysql.user;

/* D-19 패스워드 확인함수가 설정되어 적용 */
/* D-03 패스워드의 사용기간 및 복잡도를 기관의 정책에 맞도록 설정 */
SHOW VARIABLES LIKE '%validate_password%';

/* D-03 패스워드의 사용기간 및 복잡도를 기관의 정책에 맞도록 설정 */
/* 패스워드 사용기간, 마지막 변경일 
MySQL 5.7 이상*/
SELECT user,host,plugin,password_lifetime,password_last_changed,password_expired FROM mysql.user;

/* 최대사용기간-만료기간 : 90 양호
MariaDB (v10.4 이상) 
MySQL 5.7 이상
취약 : 0 또는 NULL (무제한)*/
show variables like 'default_password_lifetime';

/* D-11 데이터베이스의 접근, 변경, 삭제 등의 감사기록이 기관의 감사기록 정책에 적합하도록 설정 */
show global variables where Variable_Name like '%general_log%' or Variable_Name like 'slow_query_log' or Variable_Name like 'long_query_time' or Variable_Name like 'long_query_time' or Variable_Name like '%log_output%';
show global variables like 'audit%';

/* D-05 원격에서 DB 서버로의 접속 제한 */
SELECT user,host FROM mysql.user;

/* D-10 데이터베이스에 대해 최신 보안패치와 밴더 권고사항을 모두 적용 */
SELECT version();

/* D-06 DBA이외의 인가되지 않은 사용자가 시스템 테이블에 접근할 수 없도록 설정 */
/* Check the mysql.user table (over v.8.x)*/
select user,host,password_expired,password_last_changed,password_lifetime,account_locked,Password_reuse_time,Super_priv from mysql.user;

/* Check the mysql.user table (under v.5.x)*/
select user,host,password_expired from mysql.user;

/* Check the mysql.db */
select * from mysql.db;

/* Check the mysql.tables_priv */
select * from mysql.tables_priv;

select user, host, Select_priv, Insert_priv, Update_priv, Delete_priv, Create_priv, Drop_priv from mysql.user where (Select_priv = 'Y') or (Insert_priv = 'Y') or (Update_priv = 'Y') or (Delete_priv = 'Y') or (Create_priv = 'Y') or (Drop_priv = 'Y');

/* D-12 패스워드 재사용에 대한 제약 설정 */
/* Mysql v8.x 이상 */
show global variables where Variable_Name like 'password_history' or Variable_Name like 'password_reuse_interval';

/* D-13 DB 사용자 계정을 개별적으로 부여하여 사용 
인터뷰 항목 */
SELECT user,host FROM mysql.user;

/* D-17 데이터베이스의 주요 설정파일, 패스워드 파일 등과 같은 주요 파일들의 접근 권한이 적절하게 설정 *
/* 시스템 파일 권한 확인 항목 */
show global variables like 'datadir';

show global variables like 'log_error';

show global variables like 'general_log_file';

show global variables like 'audit_log_file';

/* D-21 인가되지 않은 GRANT OPTION 사용 제한 */
/* Over (v.8.0, v5.6) */
SELECT user,grant_priv FROM mysql.user;

/* D-20 인가되지 않은 Object Owner의 제한 */
SELECT OBJECT_TYPE,OBJECT_SCHEMA,OBJECT_NAME FROM (SELECT 'TABLE' AS OBJECT_TYPE ,TABLE_NAME AS OBJECT_NAME,TABLE_SCHEMA AS OBJECT_SCHEMA FROM information_schema.TABLES UNION SELECT 'VIEW' AS OBJECT_TYPE,TABLE_NAME AS OBJECT_NAME,TABLE_SCHEMA AS OBJECT_SCHEMA FROM information_schema.VIEWS UNION SELECT 'INDEX[Type:Name:Table]' AS OBJECT_TYPE,CONCAT (CONSTRAINT_TYPE,' : ',CONSTRAINT_NAME,' : ',TABLE_NAME) AS OBJECT_NAME,TABLE_SCHEMA AS OBJECT_SCHEMA FROM information_schema.TABLE_CONSTRAINTS UNION SELECT ROUTINE_TYPE AS OBJECT_TYPE,ROUTINE_NAME AS OBJECT_NAME,ROUTINE_SCHEMA AS OBJECT_SCHEMA FROM information_schema.ROUTINES UNION SELECT 'TRIGGER[Schema:Object]' AS OBJECT_TYPE,CONCAT (TRIGGER_NAME,' : ',EVENT_OBJECT_SCHEMA,' : ',EVENT_OBJECT_TABLE) AS OBJECT_NAME, TRIGGER_SCHEMA AS OBJECT_SCHEMA FROM information_schema.triggers) R;



