# Sniffer

Программа для отслеживания входящего трафика.

Для работы необходимы библиотеки: 
      libpcap (https://www.tcpdump.org/)
      boost (https://www.boost.org/users/download/)
И программа CMake (https://cmake.org/)
      
Программа перехватывает пакеты, поступающие на соответвующие порты (80 - http, 443 - https) и выводит информацию о них в консоль.
Данные - IP источника и его порт, IP пункта назначения и его порт, размер пакета.
Помимо этого, в конце работы программы в дирректории с бинарником создается файл Statistic.txt. В него записывается информация о полученых пакетах. Данные сгруппированы по IP пункта назначения (У пакетов с одинаковыми IP П.Н. суммируются их размер и подсчитывается их количество). В начле файла указано сколько всего перехвачено трафика и пакетов.

Проблемы: 
       Описанные ниже проблемы проявляются только в случает прохождения большого количества трафика через сеть (Видео на ютуб в высоком качестве). При простом серфинге (Пробовал на Википедии) обвала вкладок не происходит, программа работает отложенное время и в фал записываются все отсортированные данные.
      1) В коде программы прописано работать 1 минуту, однако время работы может быть другой. Были случаи, когда программа отрабатывала всего 20 секнд и завершалась и когда программа работала больше двух минут. Причину найти не удалось.
      2) Программа может обваливать вкладки. Были случаи когда браузер (FireFox) закрывался полностью или на экране появлялось сообщение "Вкладка только что упала". Причину так же выявить не удалось.
      3) При записи в файл записывается только 150-160 строк. В случаях когда пакетов очень много в файл записываются не все. Причину так же найти не удалось. 
     
                  
                  Работу стоит начать с установки дополнительного ПО
1) Установка Cmake:
      В терминале выполняем команду: sudo apt install cmake
 Готово.
 
 2) Установка libpcap:
      sudo apt-get install libpcap-dev
 Готово.
 
 3) Установка boost: (Самый долгий этап)
      Скачиваем архив с сайта выше. Распаковываем его. Открываем разархивированную папку в терминале. Выполняем команды
      sudo./bootstrap.sh. 
      sudo ./b2 install
 Готово.
 
 Далее скачиваем файлы репозитория. В папке с файлами создаем директорию build, открываем ее в терминале и выполняем команды:
      cmake ..
      cmake --build
      make
      
Программа собрана и готова к запуску!
      В этой же дирректории запускаем программу:
      sudo ./mypr
