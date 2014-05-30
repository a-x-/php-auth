#!/bin/zsh
#

# Вывод токенов из директории, кроме словаря
grep -rPwho --exclude-dir=translations "(WORDING|MESSAGE)_[A-Z0-9_]+" . | sort | uniq

# Вывод токенов из словаря
 rm /var/www/newstore.alenabrandis.com/trans0&&grep -rPwho "(WORDING|MESSAGE)_[A-Z0-9_]+" .|sort|uniq>/var/www/newstore.alenabrandis.com/trans0

# Вывод токенов, присутствующих в словаре, но не в директории
diff /var/www/newstore.alenabrandis.com/trans0 /var/www/newstore.alenabrandis.com/trans|grep -P -oh "(?<=< ).+$"

# Вывод токенов, присутствующих в директории, но не в словаре
diff /var/www/newstore.alenabrandis.com/trans0 /var/www/newstore.alenabrandis.com/trans|grep -P -oh "(?<=> ).+$"