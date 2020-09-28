UPDATE `tablename` SET `user` = LOWER(HEX(`username`)) WHERE `id` BETWEEN 0 AND 0;
UPDATE `tablename` SET `password` = LOWER(HEX(`password`)) WHERE `id` BETWEEN 0 AND 0;