/*==============================================================================
! RSA SecurID Implementation (Simplified/Insecure)
! Simplified RSA SecurID for Learning Purposes
! Supports two factor authentication and timer synchronisation of ONE user only.
!
! SecurID: Algorithmic computation
!
! Date: 7th April 2020
! Author: Yutian (Yolanda) Li
==============================================================================*/

/* 
 * Hardcoded user_id, user_pin, serial_id and seed values
 * Realistically, Organisation Database would map USER_ID to a SERIAL_ID then
 * request to secure RSA Database would map SERIAL_ID to SEED (shared secret key)
 * to ensure there are no repeated values.
 */
#define SEED 1 /* Simplified system supports only ONE user */

/* Interval in seconds to generate auth code */
#define INTERVAL 60

int generate_authentication_code(int seed, int curr_time);