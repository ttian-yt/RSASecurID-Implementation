/*==============================================================================
! RSA SecurID Implementation (Simplified/Insecure)
! Simplified RSA SecurID for Learning Purposes
! Supports two factor authentication and timer synchronisation of ONE user only.
! 
! USER: ./token <serial_id> <seed> <start_time>
!
! Date: 7th April 2020
! Author: Yutian (Yolanda) Li
==============================================================================*/

#include "securid.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* Mimic hard token intialisation */
int serial_id;
int seed;
int start_time;
int curr_time;

void delay(int num_sec);

/* 
 * RSA SecurID Token
 * Mimic soft/hard token initialisation that would be done by RSA SecurID
 * before the tokens are sent out/put into use. Organisations using these
 * would then map SERIAL_ID to a USER_ID in their own database.
 * Prints new authentication code every 60 seconds.
 */
int main(int argc, char *argv[])
{
	/* Inputs Used to Mimic Initialisation:
	 * serial_id = unique to user, kept by company database
	 * seed = shared secret key (KEPT SECRET, embedded in hard token)
	 * start_time = token initialisation time
	 */
	if (argc != 4) {
		printf("Usage: ./token <serial_id> <seed> <start_time>\n");
		return(EXIT_FAILURE);
	}

	/* Save intialisation inputs */
	serial_id = atoi(argv[1]);
	seed = atoi(argv[2]);
	start_time = atoi(argv[3]);
	curr_time = start_time;
	
	while (1) {
		/* Generate auth code */
		int auth_code = generate_authentication_code(seed, curr_time);
		/* Print auth code */
		printf("%d at time %d\n", auth_code, curr_time); //TODO change
		curr_time += INTERVAL; /* Increment interval */
		delay(INTERVAL); /* Delay for interval */
	}
	
	return(EXIT_SUCCESS);
}

/*
 * Delay for num_sec
 * Note: accurate when testing by eye
 */
void delay(int num_sec) { 
    /* Converting time into processor seconds given by clock() */
    int processor_sec = CLOCKS_PER_SEC * num_sec; 
  
    /* Storing start time */
    clock_t start_time = clock(); 
  
    /* Loop till required time reached */
    while (clock() < start_time + processor_sec) 
        ; 
}