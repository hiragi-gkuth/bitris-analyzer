CREATE TABLE `tablename` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `result` varchar(20) DEFAULT NULL,
  `user` varchar(64) DEFAULT NULL,
  `password` varchar(128) DEFAULT NULL,
  `ip` varchar(16) DEFAULT NULL,
  `authtime` double DEFAULT NULL,
  `detect` varchar(6) DEFAULT NULL,
  `rtt` double DEFAULT NULL,
  `unixtime` bigint(20) DEFAULT NULL,
  `usec` int(12) DEFAULT 0,
  `kex` double DEFAULT NULL,
  `newkey` double DEFAULT NULL,
  PRIMARY KEY (`id`)
);