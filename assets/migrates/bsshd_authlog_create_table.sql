CREATE TABLE `tablename` (
	`id` BIGINT NOT NULL AUTO_INCREMENT,
	`sessionid` VARCHAR(128) NOT NULL DEFAULT NULL,
	`clientver` VARCHAR(256) NOT NULL DEFAULT NULL,
	`user` VARCHAR(1024) NOT NULL DEFAULT '',
	`password` VARCHAR(1024) NOT NULL DEFAULT '',
	`ip` VARCHAR(46) NOT NULL,
	`authtime` DOUBLE NOT NULL,
	`rtt` DOUBLE NOT NULL,
	`unixtime` BIGINT NOT NULL,
	`usec` INT(12) NOT NULL DEFAULT '0',
	`trycount` INT,
	UNIQUE KEY `id_idx` (`id`) USING BTREE,
    KEY `sessionid_idx` (`sessionid`) USING BTREE,
    KEY `sessionid_trycount_idx` (`sessionid`,`trycount`) USING BTREE,
	PRIMARY KEY (`id`)
);