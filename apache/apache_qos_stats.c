#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define _XOPEN_SOURCE 500
#include <time.h>

#include <sys/types.h>
#include <sys/stat.h>

#define max(a,b)	((a > b)? a : b)

static char* config_logfile = "/usr/local/apache/logs/qsaudit_log";
static char* config_historyfile = "/var/log/munin/apache_qos_stats_pos";

void print_config();
void parse_qosdata();
char** strsplit(const char* str,const char* delim,int max);
void freesplit(char** tokens,int max);

int main(int argc, char** argv) {

  // check for config case
  if(argc > 1 && strcmp(argv[1],"config") == 0) {
    print_config();
  } else {
    parse_qosdata();
  }

  return 0;
}

void print_config() {
  printf("multigraph qos_connections\n");
  printf("graph_category apache\n");
  printf("graph_title QoS Access Stats\n");
  printf("graph_vlabel concurrent accesses per second\n");
  printf("qoscrmax.label max requests\n");
  printf("qoscrmax.type GAUGE\n");
  printf("qoscrmax.draw LINE1\n");
  printf("qoscravg.label avg requests\n");
  printf("qoscravg.type GAUGE\n");
  printf("qoscravg.draw LINE1\n");

  printf("multigraph qos_latency\n");
  printf("graph_category apache\n");
  printf("graph_title QoS Access Latency\n");
  printf("graph_vlabel average latency in ms\n");
  printf("graph_args --base 1000 --upper-limit 30000 --rigid\n");
  printf("qoslatmax.label max latency\n");
  printf("qoslatmax.type GAUGE\n");
  printf("qoslatmax.draw LINE1\n");
  printf("qoslatavg.label avg latency\n");
  printf("qoslatavg.type GAUGE\n");
  printf("qoslatavg.draw LINE1\n");
}

void parse_qosdata() {
  FILE* 	log_file;
  FILE*		history_file;
  char 		entry[1024];

  int 		result_cr_max = 0;
  int		result_cr_avg = 0;

  int		result_con_max = 0;
  int		result_con_avg = 0;

  int		result_lat_max = 0;
  int		result_lat_avg = 0;

  time_t	now;
  int		counts 		= 0;;
  int		status;

  log_file = fopen(config_logfile,"r");
  if(!log_file) {
    printf("unable to open data file\n");
    exit(1);
  }

  history_file = fopen(config_historyfile,"r+");
  if(history_file != NULL) {
    if(fgets(entry,sizeof(entry),history_file)) {
      int               offset = atoi(entry);
      struct stat       finfo;

      status = fstat(fileno(log_file),&finfo);
      if(status == 0 && finfo.st_size >= offset) {
        fseek(log_file,offset,SEEK_SET);
      }
    }
  }

  now = time(NULL);
  while(fgets(entry,sizeof(entry),log_file)) {
    char**	tokens;
    char	timestring[128];
    struct tm	t;
    time_t	logtime;

    //printf("test: %s\n",entry);
    tokens = strsplit(entry," ",15);

    // read timestamp and eval if line applies
    strptime(tokens[0],"[%d/%b/%Y:%T",&t);
    logtime = mktime(&t);
    if(now - logtime <= 300) {
      int	val_cr;
      int	val_con;
      int	val_lat;

      counts++;

      val_cr  = atoi(tokens[4]);
      val_con = atoi(tokens[9]);
      val_lat = atoi(tokens[10]);      
      //printf("test: %d / %d / %d\n",val_cr,val_con,val_lat);
      
      result_cr_max = max(result_cr_max,val_cr);
      result_con_max = max(result_con_max,val_con);
      result_lat_max = max(result_lat_max,val_lat);

      result_cr_avg += val_cr;
      result_con_avg += val_con;
      result_lat_avg += val_lat;
    }
    
    freesplit(tokens,15); 
  }

  if(history_file != NULL) {
    fseek(history_file,0,SEEK_SET);
    fprintf(history_file,"%d",ftell(log_file));
    fclose(history_file);
  } else {
    history_file = fopen(config_historyfile,"w");
    if(history_file != NULL) {
      fprintf(history_file,"%d",ftell(log_file));
      fclose(history_file);
    }
  }

  fclose(log_file);

  printf("multigraph qos_connections\n");
  printf("qoscrmax.value %d\n",result_cr_max);
  printf("qoscravg.value %d\n",result_cr_avg/counts);
  printf("qosconmax.value %d\n",result_cr_max);
  printf("qosconavg.value %d\n",result_cr_avg/counts);

  printf("multigraph qos_latency\n");
  printf("qoslatmax.value %d\n",result_lat_max);
  printf("qoslatavg.value %d\n",result_lat_avg/counts);
}

char** strsplit(const char* str,const char* delimiter,int max) {
  char**	result;
  char*		workstring;
  int		count 	= 0;
  int		i;

  workstring = strdup(str);

  result = malloc(sizeof(char*) * max);
  if(!result) {
    return(NULL); 
  }

  for(i=0;i<max;i++) {
    char* token = strtok((i == 0)?workstring : NULL,delimiter);
    if(!token) {
      for(;i<max;i++) {
        result[i] = NULL;
      }
      return(result);
    }
    result[i] = strdup(token);
  }

  return(result);
}

void freesplit(char** tokens,int size) {
  int i;

  for(i=0;i<size;i++) {
    if(tokens[i] != NULL) {
      free(tokens[i]);
    }
  }
  free(tokens);
}

