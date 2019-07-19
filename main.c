#include <stdio.h>
#include <stdlib.h>
#include <pcap/pcap.h>


void dispatcher_handler(u_char *,const struct pcap_pkthdr *, const u_char *);

void usage();

int main(int argc, char **argv) {
    // задаем необходимые переменные:
    pcap_t *fp;// дескриптор адаптера
    char error[PCAP_ERRBUF_SIZE],// буфер для хранения описания ошибок
        *device=NULL,// имя устройства адаптера
        *ifilename=NULL,
        *ofilename=NULL,
        *filter=NULL;
    int i=0;
    pcap_dumper_t *dumpfile;// дескриптор выходного файла
    struct bpf_program fcode;// описываем структуру
    bpf_u_int32 SubNet, NetMask;

    // не заданы параметры - выход
    if (argc == 1) {
        usage();
        return 0;
    }

    // обрабатываем аргументы командной строки
    for(i=1;i<argc;i+=2) {
        switch (argv[i] [1]) {
            case 'i':
                device=argv[i+1];
                break;
            case 'f':
                ifilename=argv[i+1];
                break;
            case 'o':
                ofilename=argv[i+1];
                break;
            case 'p':
                filter=argv[i+1];
                break;
        }
    }

    //начинаем процесс захвата пакетов из сети
    if (device != NULL) {
        if ( (fp= pcap_open_live(device, 1514, 1, 20, error)) == NULL ) {
              fprintf(stderr,"\nНевозможно открыть адаптер.\n");
              return 0;
        }
    }
    //или пробуем начать обрабатывать файл оффлайн
    else if (ifilename != NULL) {
        if ( (fp = pcap_open_offline(ifilename, NULL)) == NULL ) {
              fprintf(stderr,"\nUnable to find input file.\n");
              return 0;
        }
    }
    else usage();

    if(filter!=NULL) {
        //получаем адрес подсети
        if(device!=NULL) {
              if(pcap_lookupnet(device, &SubNet, &NetMask, error)<0) {
                    fprintf(stderr,"\nНевозможно определить маску сети.\n");
                    return 0;
              }
        }
        else NetMask=0xffffff; //Если обрабатываем файл, подразумевается, что мы работаем с подсетью класса C

        //Компилируем фильтр
        if(pcap_compile(fp, &fcode, filter, 1, NetMask)<0) {
              fprintf(stderr,"\nОшибка компиляции фильтра: неверный синтаксис.\n");
              return 0;
        }
        //Устанавливаем откомпилированный фильтр
        if(pcap_setfilter(fp, &fcode)<0) {
              fprintf(stderr,"\nОшибка при установке фильтра\n");
              return 0;
        }
    }
    //Открываем файл для дампа пакетов
    if (ofilename != NULL) {
        dumpfile=pcap_dump_open(fp, ofilename);
        if(dumpfile==NULL) {
              fprintf(stderr,"\nНевозможно открыть выходной файл\n");
              return 0;
        }
    }
    else usage();
    //Все готово – начало работы!!!
    pcap_loop(fp, 0, dispatcher_handler, (unsigned char *)dumpfile);
}

//Сетевую ловушку нужно вызывать для каждого входящего пакета
void dispatcher_handler(u_char *dumpfile, const struct pcap_pkthdr *header, const u_char *pkt_data) {
      //u_int i=0;
      printf("caplen - %d len - %d\n%s", header->caplen, header->len, (char*) pkt_data);
      //Записываем пакет в файл
      pcap_dump(dumpfile,header,pkt_data);

      //следующая инструкция принудительно записывает принятый пакет на диск.
      //Заметьте, что вызов этой функции для принудительной записи каждого пакета гарантирует когерентность записи и приема пакетов из сети
      //но снижает общую производительность.
      fflush((FILE*)dumpfile);
}

void usage() {
    printf("\nВызов:\npf [-i интерфейс] | [-f имя_входного_файла] -o имя_выходного_файла -p пакетный_фильтр\n\n");
    exit(0);
}
