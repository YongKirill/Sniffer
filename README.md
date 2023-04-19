# Sniffer

Программа для отслеживания входящего трафика.

Для работы необходимы библиотеки: 
      libpcap (https://www.tcpdump.org/)
      boost (https://www.boost.org/users/download/)
      
Программа перехватывает пакеты, поступающие на соответвующие порты (80 - http, 443 - https) и выводит информацию о них в консоль.
Данные - IP источника и его порт, IP пункта назначения и его порт, размер пакета.
Помимо этого, в конце работы программы в дирректории с бинарником создает файл Statistic.txt. В него записывается информация о полученых пакетах. Данные сгруппированы по IP пункта назначения (У пакетов с одинаковыми IP П.Н. суммируются их размер и подсчитывается их количество).

1) Установка Cmake
      В терминале выполняем команду: sudo apt install cmake
