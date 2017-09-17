#include<stdio.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/user.h> /*ptrace*/
#include <sys/reg.h> /*ORIG_EAX*/
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>
#include<errno.h>

int skip_exec = 1;
int flag_openat = 1;
int file_no = 0;
int len;
struct user_regs_struct regs;

typedef struct file_param{
  char perm[3];
  char * name;
}file_param;

char * file_nm(void * regs_rdi, pid_t pid);

int perm_check(int p0, int p1, int p2, int req_perm, int exec_perm);

void syscall_open(pid_t pid, file_param ** P1);

void syscall_openat(pid_t pid, file_param ** P1);

void syscall_execve(pid_t pid, file_param ** P1);

void syscall_creat(pid_t pid, file_param ** P1);

void syscall_mkdir(pid_t pid, file_param ** P1);

void syscall_unlinkat(pid_t pid, file_param ** P1);

void syscall_mkdirat(pid_t pid, file_param ** P1);

void main(int argc, char *argv[])
{
  pid_t pid;
  int flag1 = 1, flag2 = 1, flag3 = 1, flag4 = 1, flag5 = 1, flag6 = 1, flag7 = 1, flag8 = 1;
  int status, n1, n2;
  char *args[10];
  char config_file[256]; //stores name of config file from cmd
  
  char c1[1000],ch12;
  int i1, j1;
  FILE *fptr;
 
  if (strcmp(argv[1], "-c") == 0){
    strcpy(config_file, argv[2]);
  }
  else{
    int config_flag = 0;
    int access_flag = 0;
    char * pwd1 = (char *)malloc(256);
    getcwd(pwd1, 256);  //pwd1 will contain name of pwd
    char fendrc[] = "/.fendrc";
    strcat(pwd1, fendrc);
    //printf("PWD %s\n", pwd1);
    int access_pwd = access(pwd1, F_OK);
    //printf("PWD ACCESS VALUE %d\n", access_pwd);
    if(access_pwd == 0){ //.fendrc found in current directory
      access_flag = 1;
      config_flag = 1;  //config file found here
      strcpy(config_file, pwd1);
      //printf("Config file found in PWD\n");
    }
    if(access_flag == 0){  //not present in pwd and so checking in home dir
      char * home1 = (char *)malloc(256);
      home1 = getenv("HOME");
      strcat(home1, fendrc);
      //printf("HOME %s\n", home1);
      int access_home = access(home1, F_OK);
      if(access_home == 0){
	config_flag =1;   //config file found here
	strcpy(config_file, home1);
	//printf("Config file found in home dir\n");
      }
    }
    if(config_flag == 0){
      printf("Must provide a config file\n");
      return 0;
    }
  }


  pid = fork();
  if(pid == 0)    /////////////////////INSIDE CHILD///////////////////
    {
      ptrace(PTRACE_TRACEME, 0, NULL, NULL);
      if (strcmp(argv[1], "-c") == 0)
	{
	  //printf("1\n");
	  for(n1 = 3, n2 = 0; n1 < argc; n1++, n2++)
	    {
	      //strcpy(argv[0], argv[2]);
	      args[n2] = (char *)malloc(256);
	      strcpy(args[n2], argv[n1]);
	    }
	  args[n2] = (char *)malloc(256);
	  args[n2] = NULL; 
	}
      else{
	for(n1 = 1, n2 = 0; n1 < argc; n1++, n2++)
	  {
	    // strcpy(argv[0], argv[2]);
	    args[n2] = (char *)malloc(256);
	    strcpy(args[n2], argv[n1]);
	  }
	args[n2] = (char *)malloc(256);
	args[n2] = NULL;
      }
      execvp(args[0], args);
    }
		
	
  else     //////////////////INSIDE  PARENT/////////////////////////////////////
    {	
      // strcpy(config_file, argv[2]);
      if ((fptr=fopen(config_file,"r"))==NULL){
	printf("Error! opening file");
	exit(1);         /* Program exits if file pointer returns NULL. */
      }
      file_param * P1[1000];
	
      while ((ch12 = getc(fptr)) != EOF){
	fscanf(fptr,"%[^\n]",c1);
	P1[file_no] = (file_param *)malloc(sizeof(file_param));
	i1 = 0;
	P1[file_no]->perm[0] = ch12;
	P1[file_no]->perm[1] = c1[i1++];
	P1[file_no]->perm[2] = c1[i1++];
	while((c1[i1] == ' ') | (c1[i1] == '\t'))
	  i1++;
	P1[file_no]->name = (char *)malloc(256);
	j1 = 0;
	while(c1[i1] != '\0'){
	  *(P1[file_no]->name + j1) = c1[i1++];
	  j1++;
	}
	if(c1[i1 - 1] == '/')
	  c1[i1-1] = '\0';
	//	char real_buf[256];
	//char * real_path = realpath(P1[file_no]->name, real_buf); //calculate realpath and store in file1
	//strcpy(P1[file_no]->name, real_buf);
	file_no ++;
	ch12 = getc(fptr);
      }
      fclose(fptr);			
		
      while(1)
	{
	  wait(&status);
	  ptrace(PTRACE_GETREGS, pid, 0, &regs);
	  ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEEXEC);
	  //printf("STATUS %d\n", xyz);
	  if(WIFEXITED(status)) //True if the process terminated normally by a call to _exit(2) or exit(3)
	    break;	    		

	  else if ((regs.orig_rax >= 0 && regs.orig_rax <= 350) || regs.orig_rax == 1000)
	    {
	      /////////OPEN SYSCALL
	      if(regs.orig_rax == 2 && flag1 == 1){
		//int call_no;
		//call_no = (regs.rsi & O_ACCMODE);
		flag1 = 0;
		syscall_open(pid, &P1);
	      }
	      else if(regs.orig_rax == 2 && flag1 == 0){
		flag1 = 1;
	      }



	      ////////OPENAT SYSCALL
	      if(regs.orig_rax == 257 && flag2 == 1){
		//int call_no;
		//call_no = (regs.rsi & O_ACCMODE);
		flag2 = 0;
		//printf("INSIDE 1st LOOP\n");
		
		
		//	printf("SYSCALL VALUE : %d\n", regs.orig_rax);
	      }
	      else if(regs.orig_rax == 257 && flag2 == 0){
		flag2 = 2;
		//printf("INSIDE 2nd LOOP\n");
		syscall_openat(pid, &P1);
		
	      }
	      else if(regs.orig_rax == 257 && flag2 == 2){
		flag2 = 1;
		//syscall_openat(pid, &P1);
		//printf("INSIDE 3rd LOOP\n");
	      }


	      /////////EXECVE SYSCALL
	      if(regs.orig_rax == 59 && flag3 == 1){
		//int call_no;
		int value = regs.rdi;
		//	printf("VALUE %d\n", value);
		//call_no = (regs.rsi & O_ACCMODE);
		flag3 = 2;
		//printf("INSIDE EXEC\n");
	
	      }
	      else if(regs.orig_rax == 59 && flag3 == 2){
		flag3 = 0;
		syscall_execve(pid, &P1);
	      }
	      else if(regs.orig_rax == 59 && flag3 == 0){
		flag3 = 1;
	      }

	      ////////CREAT SYSCALL
	      if(regs.orig_rax == 85 && flag4 == 1){
		//int call_no;
		//call_no = (regs.rsi & O_ACCMODE);
		flag4 = 0;
		syscall_creat(pid, &P1);
		//printf("SYSCALL VALUE : %d\n", regs.orig_rax);
	      }
	      else if(regs.orig_rax == 85 && flag4 == 0){
		flag4 = 1;
	      }

	      //////////MKDIR SYSCALL
	      if(regs.orig_rax == 83 && flag5 == 1){
		//int call_no;
		//call_no = (regs.rsi & O_ACCMODE);
		flag5 = 0;
		syscall_mkdir(pid, &P1);
		//printf("SYSCALL VALUE : %d\n", regs.orig_rax);
	      }
	      else if(regs.orig_rax == 83 && flag5 == 0){
		flag5 = 1;
	      }

	      //////////UNLINK SYSCALL
	      if(regs.orig_rax == 87 && flag6 == 1){
		//int call_no;
		//call_no = (regs.rsi & O_ACCMODE);
		flag6 = 0;
		syscall_mkdir(pid, &P1);
		//printf("SYSCALL VALUE : %d\n", regs.orig_rax);
	      }
	      else if(regs.orig_rax == 87 && flag6 == 0){
		flag6 = 1;
	      }


	      /////////UNLINKAT SYSCALL
	      if(regs.orig_rax == 263 && flag7 == 1){
		//int call_no;
		//call_no = (regs.rsi & O_ACCMODE);
		flag7 = 0;
		syscall_unlinkat(pid, &P1);
	      }
	      else if(regs.orig_rax == 263 && flag7 == 0){
		flag7 = 1;
	      }

	      /////////MKDIRAT SYSCALL
	      if(regs.orig_rax == 258 && flag8 == 1){
		//int call_no;
		//call_no = (regs.rsi & O_ACCMODE);
		flag8 = 0;
		syscall_mkdirat(pid, &P1);
	      }
	      else if(regs.orig_rax == 258 && flag8 == 0){
		flag8 = 1;
	      }


	    }
	  else {
	    break;
	  }
	  ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
	}
    }
}

char * file_nm(void * regs_rdi, pid_t pid)
{
  long value1, value2;
  int call1;   //////checks the call
  int call_return; ///////checks return value of call
  int ch, i = 0;
  int mask = 127;
  //char filename[256], filename1[] = "\0"; 
  char * filenameP = (char *)malloc(256);
  char ch1;
  value1 = ptrace(PTRACE_PEEKDATA, pid, regs_rdi, NULL); //the value at regs.rdi is available in value1 in long format - convert to string
  while (value1 > 0){
    ch = value1 & mask;
    ch1 = (char)ch;
    //printf("%c", ch);
    *(filenameP + i) = ch1;
    i++;
    value1 = value1 >> 8 ;
  }
  regs_rdi ++;
  value2 = ptrace(PTRACE_PEEKDATA, pid, regs_rdi, NULL);
				
  while((value2 >> 56) & mask){
    value2 = value2 >> 56;
    ch = value2 & mask;
    ch1 = (char)ch;
    //printf("%c", ch);
    *(filenameP + i) = ch;
    //filename[i] = ch1;
    i++;
    regs_rdi++;
    value2 = ptrace(PTRACE_PEEKDATA, pid, regs_rdi, NULL);
  }
  *(filenameP + i) = '\0';
  len = i;
  if(*(filenameP + i - 1) == '/'){
    *(filenameP + i -1) = '\0';
    len--;
  }
  return filenameP;
}

void syscall_open(pid_t pid, file_param ** P1){
  char * file1;
  // printf("Inside OPEN");
  file1 = file_nm(regs.rdi, pid);
  int file_no1 = file_no;
  // printf("FILENAME : %s \n", file1);
  int file_flag = 0;
  while(file_no1 != 0){
    file_no1--;
    if(fnmatch(P1[file_no1]->name, file1, 0) == 0){
      file_flag = 1;
      break;
    }
    //printf("No of elements %d\n", file_no);
    //printf("Found at position %d\n", file_no1);
  }
  int call_flag = 1;
  int req_perm;
  int skip_flag = 1;
  if(file_flag == 1){  //file found in config file    

    // printf("FILE BEING TRACED : %c%c%c %s \n", P1[file_no1]->perm[0], P1[file_no1]->perm[1], P1[file_no1]->perm[2], P1[file_no1]->name);
    // call_flag = 0;   
    int p0 = P1[file_no1]->perm[0] - '0';
    int p1 = P1[file_no1]->perm[1] - '0';
    int p2 = P1[file_no1]->perm[2] - '0';
    req_perm = (regs.rsi & O_ACCMODE); //type of call 0(read) 1(write) 2(rd-wr)
    int o_create_flag = (regs.rsi & O_CREAT);
    if((req_perm == 0) && (o_create_flag != 0)){
      req_perm = 2;
    }
    skip_flag = perm_check(p0, p1, p2, req_perm, 0);
  }
  //printf("Final callflag value %d\n", call_flag);
  if(skip_flag == 0){ 	//call_flag = 0 if call is to be skipped								
    regs.orig_rax = 1000; /////modifying the syatem call number
    regs.rax = -EACCES;
    //  printf("Modified value of SYSCALL  %d\n", regs.orig_rax);
    //printf("\nNot allowed to OPEN : %s", P1[file_no1]->name);
    ptrace (PTRACE_SETREGS, pid, 0, &regs);
  }
}

void syscall_openat(pid_t pid, file_param ** P1){
  //printf("INSIDE OPENAT\n");
  char * file1;
  file1 = file_nm(regs.rsi, pid);
  int fd1 = regs.rdi;
  if(file1[0] != '/'){  //getting absolute path from fd and storing in file1
    if(fd1 == -100){
      //printf("INSIDE LOOP\n");
      char * pwd1 = (char *)malloc(256);
      getcwd(pwd1, 256);  //pwd1 will contain name of pwd
      int len5 = strlen(pwd1);
      pwd1[len5] = '/';
      pwd1[len5 + 1] = '\0';
      strcat(pwd1, file1);
      strcpy(file1, pwd1);
    }
    else{
      char buff[1024];
      char buff2[256];
      char buff3[30];
      strcpy(buff2, "/proc/");
      sprintf(buff3, "%d", pid);
      strcat(buff2, buff3);
      strcat(buff2, "/fd/");
      sprintf(buff3, "%d", fd1);
      strcat(buff2, buff3);
      int len1 =  readlink(buff2, buff, 1024);
      buff[len1] = '/';
      buff[len1 + 1] = '\0';
      strcat(buff, file1);
      strcpy(file1, buff);
    }
    
  }

  //char real_buf[256];
  //char * real_path = realpath(file1, real_buf); //calculate realpath and store in file1
  //strcpy(file1, real_buf);

  //char * file2 = dirname(file1);
  //strcpy(file1, file2);
  //printf("DIRNAME HERE %s\n", file1);

  int file_no1 = file_no;
  int file_flag = 0;
  while(file_no1 != 0){
    file_no1--;
    if(fnmatch(P1[file_no1]->name, file1, 0) == 0){
      file_flag = 1;
      break;
    }
  }
					
  int call_flag = 1;
  int req_perm;
  int skip_flag = 1;					
  if(file_flag == 1){  /////file_flag =1 if filename on cmd found in config file 
    //printf("FILE BEING TRACED : %c%c%c %s \n", P1[file_no1]->perm[0], P1[file_no1]->perm[1], P1[file_no1]->perm[2], P1[file_no1]->name);
    // call_flag = 0;   
    int p0 = P1[file_no1]->perm[0] - '0';
    int p1 = P1[file_no1]->perm[1] - '0';
    int p2 = P1[file_no1]->perm[2] - '0';
    req_perm = (regs.rdx & O_ACCMODE); //type of call 0(read) 1(write) 2(read-write)
    int o_create_flag = (regs.rdx & O_CREAT);
    //printf("CREAT FLAG %d\n", o_create_flag);
    //printf("REQ PERM1  %d\n", req_perm);
    if((req_perm == 0) && (o_create_flag == O_CREAT)){
      req_perm = 2;
    }
    //printf("REQ PERM %d\n", req_perm);
    skip_flag = perm_check(p0, p1, p2, req_perm, 0);
  }

  if(skip_flag == 0){ 									
    regs.orig_rax = 1000; /////modifying the syatem call number
    regs.rax = -EACCES;
    // printf("Modified value of SYSCALL  %d\n", regs.orig_rax);
    //printf("\nNot allowed to OPENAT : %s\n", P1[file_no1]->name); 
    ptrace (PTRACE_SETREGS, pid, 0, &regs);
  }
}


int perm_check(int p0, int p1, int p2, int req_perm, int exec_perm){
  int perm_flag = 0;  //0 if perm do not match
  if(exec_perm == 1){
    if(p2 == 1){
      perm_flag =1; 
    }
  }

  if(req_perm == 0){
    if(p0 == 1){
      perm_flag = 1;
    }
  }	
  else if(req_perm == 1){
    //printf("Here\n");
    if(p1 == 1){
      //printf("Call flag :\n");
      perm_flag = 1;
    }
  }
  else if(req_perm == 2){
    //printf("IN READ-WRITE\n");
    if((p0 == 1) && (p1 == 1))
      perm_flag = 1;
    //  printf("CALL FLAG IN READ-WRITE : %d\n", call_flag);
  }
  return perm_flag;
}

void syscall_execve(pid_t pid, file_param ** P1){
  // printf("INSIDE EXEC\n");
  // struct user_regs_struct regs1;
  //ptrace(PTRACE_GETREGS, pid, 0, &regs1);
  int value = regs.rdi;
  // printf("VALUE %d\n", value);
  if(value != 0){
    //printf("NOT SKIPPED PID : %d\n", pid);
    char * file1;
    //printf("Inside EXEC1\n");
    //printf("SYSCALL : %ld\n",regs.orig_rax);
    // printf("VALUE : %ld\n",regs.rdi);
    file1 = file_nm(regs.rdi, pid);
    int file_no1 = file_no;
    //printf("FILENAME : %s \n", file1);
    int file_flag = 0;
    while(file_no1 != 0){
      file_no1--;
      if(fnmatch(P1[file_no1]->name, file1, 0) == 0){
	file_flag = 1;
	break;
      }
    }
    int call_flag = 1;
    int req_perm;
    int skip_flag = 1;					
    if(file_flag == 1){  /////file_flag =1 if filename on cmd found in config file 
      // printf("FILE BEING TRACED : %c%c%c %s \n", P1[file_no1]->perm[0], P1[file_no1]->perm[1], P1[file_no1]->perm[2], P1[file_no1]->name);
      // call_flag = 0;   
      int p0 = P1[file_no1]->perm[0] - '0';
      int p1 = P1[file_no1]->perm[1] - '0';
      int p2 = P1[file_no1]->perm[2] - '0';
      if(p2 != 1){
	skip_flag = 0;
      }
      //skip_flag = perm_check(p0, p1, p2, -1, 1);
    }

    if(skip_flag == 0){ 									
      regs.orig_rax = 1000; /////modifying the syatem call number
      regs.rax = -EACCES;
      //  printf("Modified value of SYSCALL  %d\n", regs.orig_rax);
      //printf("\nNot allowed to exec : %s\n", P1[file_no1]->name); 
      ptrace (PTRACE_SETREGS, pid, 0, &regs);
    }
  }
  
}

void syscall_creat(pid_t pid, file_param ** P1){
  char * file1;
  file1 = file_nm(regs.rdi, pid);
  if(file1[0] != '/'){  //getting absolute path from fd and storing in file1
    char buff[1024];
    char buff2[256];
    char buff3[30];
    strcpy(buff2, "/proc/");
    sprintf(buff3, "%d", pid);
    strcat(buff2, buff3);
    strcat(buff2, "/cwd");
    //sprintf(buff3, "%d", fd1);
    int len1 =  readlink(buff2, buff, 1024);
    buff[len1] = '/';
    buff[len1 + 1] = '\0';
    strcat(buff, file1);
    strcpy(file1, buff);
  }
    
  //char real_buf[256];
  //char * real_path = realpath(file1, real_buf); //calculate realpath and store in file1
  //strcpy(file1, real_buf);

  //char * file2 = dirname(file1);
  //strcpy(file1, file2);
  //printf("DIRNAME HERE %s\n", file1);

  int file_no1 = file_no;
  int file_flag = 0;
  while(file_no1 != 0){
    file_no1--;
    if(fnmatch(P1[file_no1]->name, file1, 0) == 0){
      file_flag = 1;
      break;
    }
  }
					
  int call_flag = 1;
  int req_perm;
  int skip_flag = 1;					
  if(file_flag == 1){  /////file_flag =1 if filename on cmd found in config file 
    // printf("FILE BEING TRACED : %c%c%c %s \n", P1[file_no1]->perm[0], P1[file_no1]->perm[1], P1[file_no1]->perm[2], P1[file_no1]->name);
    // call_flag = 0;   
    int p0 = P1[file_no1]->perm[0] - '0';
    int p1 = P1[file_no1]->perm[1] - '0';
    int p2 = P1[file_no1]->perm[2] - '0';
    req_perm = (regs.rsi & O_ACCMODE); //type of call 0(read) 1(write) 2(read-write)
    int o_create_flag = (regs.rsi & O_CREAT);
    if((req_perm == 0) && (o_create_flag != 0)){
      req_perm = 2;
    }
    skip_flag = perm_check(p0, p1, p2, req_perm, 0);
  }

  if(skip_flag == 0){ 									
    regs.orig_rax = 1000; /////modifying the syatem call number
    regs.rax = -EACCES;
    // printf("Modified value of SYSCALL  %d\n", regs.orig_rax);
    //printf("\nNot allowed to OPENAT : %s\n", P1[file_no1]->name); 
    ptrace (PTRACE_SETREGS, pid, 0, &regs);
  }
}

void syscall_mkdir(pid_t pid, file_param ** P1){
  char * file1;
  file1 = file_nm(regs.rdi, pid);
  // printf("FILENAME %s\n", file1);
  if(file1[0] != '/'){  //getting absolute path from fd and storing in file1
    //printf("HERE\n");
    char buff[1024];
    char buff2[256];
    char buff3[30];
    strcpy(buff2, "/proc/");
    sprintf(buff3, "%d", pid);
    strcat(buff2, buff3);
    //printf("BUFFER %s\n", buff2);
    strcat(buff2, "/cwd");
    //sprintf(buff3, "%d", fd1);
    int len1 =  readlink(buff2, buff, 1024);
    // printf("LENGTH %d\n", len1);
    buff[len1] = '/';
    buff[len1 + 1] = '\0';
    //printf("BUFFER %s\n", buff2);
    strcat(buff, file1);
    strcpy(file1, buff);
  }
  // printf("FILENAME1 %s\n", file1);

  //char real_buf[256];
  //char * real_path = realpath(file1, real_buf); //calculate realpath and store in file1
  //strcpy(file1, real_buf);

  //char * file2 = dirname(file1);
  //strcpy(file1, file2);
  //printf("DIRNAME HERE %s\n", file1);

  int file_no1 = file_no;
  int file_flag = 0;
  while(file_no1 != 0){
    file_no1--;
    if(fnmatch(P1[file_no1]->name, file1, 0) == 0){
      file_flag = 1;
      break;
    }
  }
					
  int call_flag = 1;
  int req_perm;
  int skip_flag = 1;					
  if(file_flag == 1){  /////file_flag =1 if filename on cmd found in config file 
    // printf("FILE BEING TRACED : %c%c%c %s \n", P1[file_no1]->perm[0], P1[file_no1]->perm[1], P1[file_no1]->perm[2], P1[file_no1]->name);
    // call_flag = 0;   
    int p0 = P1[file_no1]->perm[0] - '0';
    int p1 = P1[file_no1]->perm[1] - '0';
    int p2 = P1[file_no1]->perm[2] - '0';
    /* req_perm = (regs.rsi & O_ACCMODE); //type of call 0(read) 1(write) 2(read-write)
       int o_create_flag = (regs.rsi & O_CREAT);
       if((req_perm == 0) && (o_create_flag != 0)){
       req_perm = 2;
       }*/
    skip_flag = perm_check(p0, p1, p2, 1, 0);
  }

  if(skip_flag == 0){ 									
    regs.orig_rax = 1000; /////modifying the syatem call number
    regs.rax = -EACCES;
    //printf("Modified value of SYSCALL  %d\n", regs.orig_rax);
    //printf("\nNot allowed to OPENAT : %s\n", P1[file_no1]->name); 
    ptrace (PTRACE_SETREGS, pid, 0, &regs);
  }

}

void syscall_unlinkat(pid_t pid, file_param ** P1){
  char * file1;
  file1 = file_nm(regs.rsi, pid);
  int fd1 = regs.rdi;
  if(file1[0] != '/'){  //getting absolute path from fd and storing in file1
    if(fd1 == -100){
      //printf("INSIDE LOOP\n");
      char * pwd1 = (char *)malloc(256);
      getcwd(pwd1, 256);  //pwd1 will contain name of pwd
      int len5 = strlen(pwd1);
      pwd1[len5] = '/';
      pwd1[len5 + 1] = '\0';
      strcat(pwd1, file1);
      strcpy(file1, pwd1);
    }
    else{
      char buff[1024];
      char buff2[256];
      char buff3[30];
      strcpy(buff2, "/proc/");
      sprintf(buff3, "%d", pid);
      strcat(buff2, buff3);
      strcat(buff2, "/fd/");
      sprintf(buff3, "%d", fd1);
      strcat(buff2, buff3);
      int len1 =  readlink(buff2, buff, 1024);
      buff[len1] = '/';
      buff[len1 + 1] = '\0';
      strcat(buff, file1);
      strcpy(file1, buff);
    }
    
  }

  //char real_buf[256];
  //char * real_path = realpath(file1, real_buf); //calculate realpath and store in file1
  //strcpy(file1, real_buf);

  //char * file2 = dirname(file1);
  //strcpy(file1, file2);
  //printf("DIRNAME HERE %s\n", file1);

  int file_no1 = file_no;
  int file_flag = 0;
  while(file_no1 != 0){
    file_no1--;
    if(fnmatch(P1[file_no1]->name, file1, 0) == 0){
      file_flag = 1;
      break;
    }
  }
					
  int call_flag = 1;
  int req_perm;
  int skip_flag = 1;					
  if(file_flag == 1){  /////file_flag =1 if filename on cmd found in config file 
    // printf("FILE BEING TRACED : %c%c%c %s \n", P1[file_no1]->perm[0], P1[file_no1]->perm[1], P1[file_no1]->perm[2], P1[file_no1]->name);
    // call_flag = 0;   
    int p0 = P1[file_no1]->perm[0] - '0';
    int p1 = P1[file_no1]->perm[1] - '0';
    int p2 = P1[file_no1]->perm[2] - '0';
    /* req_perm = (regs.rsi & O_ACCMODE); //type of call 0(read) 1(write) 2(read-write)
       int o_create_flag = (regs.rsi & O_CREAT);
       if((req_perm == 0) && (o_create_flag != 0)){
       req_perm = 2;
       }*/
    skip_flag = perm_check(p0, p1, p2, 1, 0);
  }

  if(skip_flag == 0){ 									
    regs.orig_rax = 1000; /////modifying the syatem call number
    regs.rax = -EACCES;
    //printf("Modified value of SYSCALL  %d\n", regs.orig_rax);
    //printf("\nNot allowed to OPENAT : %s\n", P1[file_no1]->name); 
    ptrace (PTRACE_SETREGS, pid, 0, &regs);
  }

}

void syscall_mkdirat(pid_t pid, file_param ** P1){
  char * file1;
  file1 = file_nm(regs.rsi, pid);
  int fd1 = regs.rdi;
  if(file1[0] != '/'){  //getting absolute path from fd and storing in file1
    if(fd1 == -100){
      //printf("INSIDE LOOP\n");
      char * pwd1 = (char *)malloc(256);
      getcwd(pwd1, 256);  //pwd1 will contain name of pwd
      int len5 = strlen(pwd1);
      pwd1[len5] = '/';
      pwd1[len5 + 1] = '\0';
      strcat(pwd1, file1);
      strcpy(file1, pwd1);
    }
    else{
      char buff[1024];
      char buff2[256];
      char buff3[30];
      strcpy(buff2, "/proc/");
      sprintf(buff3, "%d", pid);
      strcat(buff2, buff3);
      strcat(buff2, "/fd/");
      sprintf(buff3, "%d", fd1);
      strcat(buff2, buff3);
      int len1 =  readlink(buff2, buff, 1024);
      buff[len1] = '/';
      buff[len1 + 1] = '\0';
      strcat(buff, file1);
      strcpy(file1, buff);
    }
    
  }

  //char real_buf[256];
  //char * real_path = realpath(file1, real_buf); //calculate realpath and store in file1
  //strcpy(file1, real_buf);

  //char * file2 = dirname(file1);
  //strcpy(file1, file2);
  //printf("DIRNAME HERE %s\n", file1);

  int file_no1 = file_no;
  int file_flag = 0;
  while(file_no1 != 0){
    file_no1--;
    if(fnmatch(P1[file_no1]->name, file1, 0) == 0){
      file_flag = 1;
      break;
    }
  }
					
  int call_flag = 1;
  int req_perm;
  int skip_flag = 1;					
  if(file_flag == 1){  /////file_flag =1 if filename on cmd found in config file 
    // printf("FILE BEING TRACED : %c%c%c %s \n", P1[file_no1]->perm[0], P1[file_no1]->perm[1], P1[file_no1]->perm[2], P1[file_no1]->name);
    // call_flag = 0;   
    int p0 = P1[file_no1]->perm[0] - '0';
    int p1 = P1[file_no1]->perm[1] - '0';
    int p2 = P1[file_no1]->perm[2] - '0';
    /* req_perm = (regs.rsi & O_ACCMODE); //type of call 0(read) 1(write) 2(read-write)
       int o_create_flag = (regs.rsi & O_CREAT);
       if((req_perm == 0) && (o_create_flag != 0)){
       req_perm = 2;
       }*/
    skip_flag = perm_check(p0, p1, p2, 1, 0);
  }

  if(skip_flag == 0){ 									
    regs.orig_rax = 1000; /////modifying the syatem call number
    regs.rax = -EACCES;
    //printf("Modified value of SYSCALL  %d\n", regs.orig_rax);
    //printf("\nNot allowed to OPENAT : %s\n", P1[file_no1]->name); 
    ptrace (PTRACE_SETREGS, pid, 0, &regs);
  }
}
