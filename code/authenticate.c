/*==============================================================================
! RSA SecurID Implementation (Simplified/Insecure)
! Simplified RSA SecurID for Learning Purposes
! Supports two factor authentication and timer synchronisation of ONE user only.
!
! SERVER: ./authenticate <user_id> <user_pin> <authentication_code> <curr_time>
!
! Date: 7th April 2020
! Author: Yutian (Yolanda) Li
==============================================================================*/

#include "securid.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* 
 * Hardcoded user_id, user_pin, serial_id and seed values
 * Realistically, Organisation Database would map USER_ID to a SERIAL_ID then
 * request to secure RSA Database would map SERIAL_ID to SEED (shared secret key)
 * to ensure there are no repeated values.
 */
#define USER_ID 1 /* Simplified system supports only ONE user */
#define USER_PIN 1
#define SERIAL_ID 1 

int get_auth_code (int serial_id, int curr_time);
int map_serial_id_to_seed (int serial_id);
int map_user_id_pin_to_serial_id(int user_id, int user_pin);
int get_auth_code_calc_time(int serial_id, int curr_time);

/* 
 * RSA SecurID Server
 * Mimics server/website that requires the authentication
 */
int main(int argc, char *argv[])
{
	/* Inputs:
	 * user_id = unique to user
	 * authentication_code = user entered code printed by their hard/soft token
	 * user_pin = user personal pin
	 * current_time = simplification for algorithm
	 */
	if (argc != 5) {
		printf("Usage: ./authenticate <user_id> <user_pin> <authentication_code> <current_time>\n");
		return(EXIT_FAILURE);
	}
	int user_id = atoi(argv[1]);
	int user_pin = atoi(argv[2]);
	int user_auth_code = atoi(argv[3]);
	int curr_time = atoi(argv[4]);

	/* Check user_id and user_pw validity and get serial_id */
	int serial_id = map_user_id_pin_to_serial_id(user_id, user_pin);
	if (!serial_id) {
		printf("Error: User id %d or PIN is invalid.\n", user_id);
		return(EXIT_FAILURE);
	}

	/* Generate server auth code */
	int server_auth_code = get_auth_code(serial_id, curr_time);

	/* Authenticate auth_code */
	if (server_auth_code == user_auth_code) {
		printf("You have been successfully authenticated.\n");
	} else {
		/* Doesn't match, attempt to synchronise (in case time synchronisation error) */

		/* Check +- ONE interval */
		int auth_code_plus1 = get_auth_code(serial_id, curr_time + INTERVAL);
		if (auth_code_plus1 == user_auth_code) {
			printf("You have been successfully authenticated.\n");
			return(EXIT_SUCCESS);
		}
		int auth_code_minus1 = get_auth_code(serial_id, curr_time - INTERVAL);
		if (auth_code_minus1 == user_auth_code) {
			printf("You have been successfully authenticated.\n");
			return(EXIT_SUCCESS);
		}

		/* 1 interval / 3 codes failed, check for 10 interval window */
		int matched_code = 0;
		int matched_time = 0;
		for (int i = 2; i <= 10; i++) {
			/* Starting at interval +-2 to +- 10 */
			int auth_code_plus = get_auth_code(serial_id, curr_time + (i * INTERVAL));
			if (auth_code_plus == user_auth_code) {
				matched_code = auth_code_plus;
				matched_time = curr_time + (i * INTERVAL);
				break;
			}

			int auth_code_minus = get_auth_code(serial_id, curr_time - (i * INTERVAL));
			if (auth_code_minus == user_auth_code) {
				matched_code = auth_code_minus;
				matched_time = curr_time - (i * INTERVAL);
				break;
			}
		}

		/* One match found, send challenge for next authentication code in sequence
		 * Prevents brute force attacks, attacker would need to try 10^6/10^8 combinations
		 * in 60 seconds (depending on length of the combination)
		 */
		if (matched_code) {
			/* Found a match, send challenge for next code in sequence*/
			int challenge_code;
			
			printf("Please enter the next authentication code: ");
			/* Dummy algorithm, should restrict length to 6/8 digits */
			if (scanf("%d", &challenge_code) == 1) {
				/* Calculate next code */
				int next_code = get_auth_code(serial_id, matched_time + INTERVAL);
				
				if (challenge_code == next_code) {
					/* Matched */
					printf("You have been successfully authenticated.\n");
					return(EXIT_SUCCESS);
				} else {
					printf("Error: Authentication failed, authentication code incorrect.\n");
					return(EXIT_FAILURE);
				}
			} else {
				printf("Error: Authentication failed, authentication code incorrect.\n");
				return(EXIT_FAILURE);
			}
		} else {
			/* No match found */
			printf("Error: Authentication failed, authentication code incorrect.\n");
			return(EXIT_FAILURE);
		}
	}

	return(EXIT_SUCCESS);
}

/*
 * Wrapper for securid generate_authentication_code()
 * Return authentication code
 */
int get_auth_code (int serial_id, int curr_time) {
	int auth_code = 0;

	/* Get seed mapped to serial id of user */
	int seed = map_serial_id_to_seed(serial_id);

	/* Get start time of 60 second time interval for consistent calculation */
	int calc_time = get_auth_code_calc_time(serial_id, curr_time);

	/* Generate the authentication code */
	auth_code = generate_authentication_code(seed, calc_time);

	return auth_code;
}

/*
 * Maps given serial id to seed (shared secret key)
 * Separate for security purposes (should be calling different database irl)
 * Returns 0 if seed not found
 */
int map_serial_id_to_seed (int serial_id) {
	if (serial_id == SERIAL_ID) {
		return SEED;
	}
	return 0;
}

/* 
 * Maps given user_id and user_pin to serial_id
 * Returns 0 if user_id or user_pin invalid
 */
int map_user_id_pin_to_serial_id(int user_id, int user_pin) {
	if (user_id == USER_ID && user_pin == USER_PIN) {
		return SERIAL_ID;
	}
	return 0;
}

/* 
 * Given serial_id and curr_time, get starting time of 60 second interval
 */
int get_auth_code_calc_time(int serial_id, int curr_time) {
	int calc_time = 0;

	/* Input error check, time interval doesn't exist */
	if (curr_time < 0) {
		return 0;
	}

	calc_time = curr_time / INTERVAL; /* Integer divison round to 0 */
	calc_time = calc_time * INTERVAL; /* Get time in seconds */

	return calc_time;
}