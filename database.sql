#
# Table schema for MySQL
#
CREATE TABLE `urls` (
	`id` INT(10) UNSIGNED NOT NULL AUTO_INCREMENT,
	`params` JSON NULL DEFAULT NULL,
	`url` VARCHAR(1000) NOT NULL COLLATE 'latin1_swedish_ci',
	`user` VARCHAR(320) AS (json_unquote(json_extract(`params`,'$.user'))) virtual,
	`hits` INT(10) UNSIGNED NULL DEFAULT '0',
	`created` DATETIME NULL DEFAULT CURRENT_TIMESTAMP,
	`accessed` DATETIME NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
	PRIMARY KEY (`id`) USING BTREE,
	UNIQUE INDEX `url_user` (`url`, `user`) USING BTREE
)
COLLATE='latin1_swedish_ci'
ENGINE=InnoDB
AUTO_INCREMENT=16
;
