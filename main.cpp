#include <iostream>
#include <fstream>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <string.h>
#include <list>
#include <ctime>
#include <boost/log/trivial.hpp>


struct Data_Package
{
    std::string ip_src, ip_dst;
    bpf_u_int32 len;
    uint16_t source;
    uint16_t dest;
    int count = 1;
    static int total_len;
    static int total_count;


    Data_Package(std::string ip_src, std::string ip_dst, bpf_u_int32 len, uint16_t source, uint16_t dest)
    {
        this->ip_src = ip_src;
        this->ip_dst = ip_dst;
        this->len = len;
        this->source = source;
        this->dest = dest;
        total_len+=len;
        total_count++;
    }
};
int Data_Package::total_len = 0;
int Data_Package::total_count = 0;


std::ostream& operator <<(std::ostream& os, Data_Package& package)
{
    std::string unit_measure = " Bites";
    if (package.len>1024)
    {
        package.len/=1024;
        unit_measure = "Kb";
        if(package.len>1024)
        {
            package.len/=1024;
            unit_measure = "Mb";
        }
    }
    os << "Received packet with destination IP address: "
       << package.ip_dst << ":" << package.dest << std::endl
       << "Packet captured. Length: " << package.len << unit_measure << std::endl
       << "Count of pakages:  " << package.count << std::endl;
    return os;
}

void Adding( Data_Package& package, std::list <Data_Package>& Data_Package_list)
{
    if (Data_Package_list.size() == 0)
    {
        Data_Package_list.push_back(package);
    }
    else
    {
        for (auto it = Data_Package_list.begin(); it != Data_Package_list.end(); ++it)
        {
            if ((*it).ip_dst == package.ip_dst) 
            {
                (*it).len += package.len;
                (*it).count++;
                return;
            }
            // if ((package.ip_src == (*it).ip_src) && (package.ip_dst == (*it).ip_dst) && ((*it).source == package.source) && ((*it).dest == package.dest))
            // {
            //     (*it).len += package.len;
            //     (*it).count++;
            //     return;
            // }
        }
        Data_Package_list.push_back(package);        
    }
    ++package.count;
}

void packetHandler(u_char* userData, const struct pcap_pkthdr* pkthdr, const u_char* packetData, std::list <Data_Package>& Data_Package_list)
{
    // Преобразование заголовка IP-пакета
    const struct ip* ipHeader = (struct ip*)(packetData + 14); // Пропускаем заголовок Ethernet
    int ipHeaderLength = ipHeader->ip_hl << 2; // Размер заголовка IP-пакета в байтах

    // Преобразование заголовка TCP-пакета
    const struct tcphdr* tcpHeader = (struct tcphdr*)(packetData + 14 + ipHeaderLength); // Пропускаем заголовок Ethernet и IP

    std::string ip_src = inet_ntoa(ipHeader->ip_src);
    uint16_t source = ntohs(tcpHeader->source);
    std::string ip_dst = inet_ntoa(ipHeader->ip_dst);
    uint16_t dest = ntohs(tcpHeader->dest);

    //Добавление новой записи в список записей
    Data_Package record (ip_src,ip_dst, pkthdr->len, source, dest);
    Adding(record, Data_Package_list);

    //Выводим информацию о пакете
    std::cout << "Packet captured. Length: " << pkthdr->len << " Bites" << std::endl;
    std::cout << "Received a packet with an IP address and ports: " << ip_src << ":" << source << " -> " << ip_dst << ":" << dest << std::endl;   
}

std::string print_total(std::list <Data_Package>& Data_Package_list)
{
    int tot_len = (*Data_Package_list.begin()).total_len;
    int tot_packages = (*Data_Package_list.begin()).total_count;
    std::string unit_measure = "Butes";
    if(tot_len>1024)
    {
        tot_len/=1024;
        unit_measure = "KB";
        if(tot_len>1024)
        {
            tot_len/=1024;
            unit_measure= "MB";
        }
    }
    std::string total;
    total = "Total: " + std::to_string(tot_len) + " " + unit_measure + "\n       " +std::to_string(tot_packages) + " Packages" + "\n";
    return total;

}

int main(int argc, char** argv)
{
    char* dev = argv[1]; // Имя устройства для захвата трафика
    pcap_t* handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct pcap_pkthdr header;
    const unsigned char* packetData;

    // Открытие сетевого интерфейса на прослушивание
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr)
    {
        BOOST_LOG_TRIVIAL(error) << "An error severity message"<< errbuf << std::endl;
        return 1;
    }

    //Установка и настройка фильтра 
    {   
    struct bpf_program fp;
    const char* filter = "port 443";// 80 - http, 443 - htpps
    bpf_u_int32 net;
    if (pcap_compile(handle, &fp, filter, 0, net) == -1)
    {
        BOOST_LOG_TRIVIAL(error) << "Error compiling filter: " << pcap_geterr(handle) << std::endl;
        return 1;
    }
    if (pcap_setfilter(handle, &fp) == -1)
    {
        BOOST_LOG_TRIVIAL(error) << "Error setting filter: " << pcap_geterr(handle) << std::endl;
        return 1;
    }
    }

    BOOST_LOG_TRIVIAL(info) <<  "Program started! "<<std::endl;
    std::list <Data_Package> Data_Package_list;
    std::string path = "Statistic.txt";
    
    std::ofstream fout;
    fout.open(path);
    if (!fout.is_open()) { BOOST_LOG_TRIVIAL(error)<<"Ошибка открытия файла для записи статистики!"<<std::endl; return 1;}
    


    // Запуск бесконечного цикла прослушивания
    int start = clock(); // засекаем время старта

    while (true)
    {
        packetData = pcap_next(handle, &header);
        packetHandler(nullptr, &header, packetData, Data_Package_list);
        int end = clock(); //Обновляем текущее время
        if (end - start > 60000) //Разница времени в мс
        {
            std::cout << (double)(end - start) / CLOCKS_PER_SEC * 1000 <<" sec"<<std::endl;
            break;
        }
    }
    pcap_close(handle);

    fout<<print_total(Data_Package_list);

    for (auto it = Data_Package_list.begin(); it != Data_Package_list.end(); ++it)
    {
        fout<<(*it)<<std::endl;
    }
    
    fout.close();

    return 0;
}
