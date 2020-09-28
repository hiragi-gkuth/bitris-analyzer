INSERT INTO `tablename`(id,result,user,`password`,ip,authtime,detect,rtt,unixtime,kex,newkey) 
SELECT id, result, user, `password`, ip, authtime, detect, rtt,
  UNIX_TIMESTAMP(auth_at) as unixtime,
  kex,
  newkey
from `tablename_from`;