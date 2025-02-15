#include <Arduino.h>
#include <Crypto.h>
#include <SHA512.h>
#define add Ed25519_add
#define sub Ed25519_sub
#define modulo Ed25519_modulo
typedef struct {unsigned char Ed[32]; } field_element;
extern "C"
{
  void sub(field_element *r, const field_element *x, const field_element *y);
  void add(field_element *r, const field_element *x, const field_element *y);
  void modulo(field_element *r, unsigned char *C);
  char Ed_num_sub_prime(unsigned char* r, const unsigned char* a);
  char Ed25519_square(unsigned char* r, const unsigned char* a);
  char Ed_mul(unsigned char* r, const unsigned char* a, const unsigned char* b);
}
void in_range(field_element *r);
void flip_if(field_element *r, const field_element *x, unsigned char b);
void mul(field_element *r, const field_element *x, const field_element *y);
void square(field_element *r, const field_element *x);
void M_Inverse_Z(field_element *r, const field_element *x);
field_element prime = {{0xED, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F}};
field_element Gx = {{0x1A, 0xD5, 0x25, 0x8F, 0x60, 0x2D, 0x56, 0xC9, 0xB2, 0xA7, 0x25, 0x95, 0x60, 0xC7, 0x2C, 0x69, 0x5C, 0xDC, 0xD6, 0xFD, 0x31, 0xE2, 0xA4, 0xC0, 0xFE, 0x53, 0x6E, 0xCD, 0xD3, 0x36, 0x69, 0x21}};
field_element Gy = {{0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66}};
field_element Gt = {{0xA3, 0xDD, 0xB7, 0xA5, 0xB3, 0x8A, 0xDE, 0x6D, 0xF5, 0x52, 0x51, 0x77, 0x80, 0x9F, 0xF0, 0x20, 0x7D, 0xE3, 0xAB, 0x64, 0x8E, 0x4E, 0xEA, 0x66, 0x65, 0x76, 0x8B, 0xD7, 0x0F, 0x5F, 0x87, 0x67}};
field_element Gz = {{0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}};
field_element public_key_x = {{0xDB, 0x6E, 0x3E, 0x8A, 0xB2, 0x7D, 0x9A, 0x9A, 0x7B, 0x83, 0x8B, 0xD8, 0xCA, 0xB6, 0x2D, 0x12, 0x72, 0x3B, 0x7A, 0x0B, 0xE9, 0x77, 0x6C, 0x7B, 0xF7, 0xA1, 0xDE, 0x8E, 0xC7, 0xF6, 0x03, 0x74}};
field_element public_key_y = {{0xCA, 0x98, 0x4A, 0x94, 0x7E, 0xCB, 0x50, 0x29, 0x24, 0x7E, 0xAB, 0x25, 0x72, 0xC3, 0x23, 0xD5, 0x9D, 0x42, 0x4C, 0x01, 0xA6, 0xFC, 0x78, 0x1F, 0xF0, 0x2E, 0x1E, 0x72, 0x8A, 0xEF, 0xAF, 0x33}};
field_element public_Nonce_x = {{0xD3, 0xE3, 0xBF, 0x9E, 0x5C, 0x31, 0xB4, 0xD4, 0x26, 0xFE, 0x49, 0xFF, 0x9C, 0x73, 0x7E, 0xC4, 0x0B, 0x7B, 0xD3, 0x51, 0xE6, 0x65, 0x9E, 0x52, 0xC5, 0x2D, 0xD1, 0x4F, 0x45, 0xD1, 0x3C, 0x4E}};
field_element public_Nonce_y = {{0xCC, 0xC3, 0x4B, 0x0B, 0x58, 0xA9, 0x94, 0xE8, 0xA9, 0x3B, 0x2A, 0x0B, 0xF3, 0x9D, 0xBF, 0x07, 0x2A, 0xA4, 0xC4, 0x0C, 0x43, 0xEA, 0x9C, 0xBC, 0x37, 0x53, 0xC9, 0xEC, 0x42, 0x84, 0x85, 0x7C}};
//Authenticated signature
unsigned char signature[64] = {0x7C, 0x8D, 0x3D, 0xF2, 0x48, 0xF5, 0x0A, 0x89, 0xE9, 0xA8, 0x22, 0xEB, 0x45, 0xF0, 0x96, 0xF4, 0xAD, 0x7A, 0xC4, 0xB4, 0x3B, 0xCB, 0xBD, 0x2B, 0xE2, 0x99, 0x3C, 0x15, 0x77, 0xDA, 0xEA, 0xA4, 0x46, 0x61, 0xF4, 0x13, 0x9A, 0x26, 0xEC, 0x22, 0xE3, 0x6A, 0xBE, 0x4F, 0x4A, 0xA2, 0x06, 0x7A, 0xCC, 0x11, 0x49, 0x9C, 0xC4, 0x53, 0x79, 0x17, 0xF1, 0x39, 0x5F, 0x3E, 0xCB, 0x61, 0x25, 0x01};
uint8_t message[] = {0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x20, 0x77, 0x6F, 0x72, 0x6C, 0x64}; // "Hello world !" ASCII
field_element xr, yr, tr, zr;
int main()
{
  Serial.begin(500000);
  Serial.println();
  bool result = verify_signature(sizeof(message));
  Serial.println(" ");
  Serial.print("The Signature: ");
  for (int i = 0; i < 64; i++)
  {
    if (signature[i] < 16) Serial.print("0");
    Serial.print(signature[i], HEX);
    Serial.print(" ");
  }
  Serial.println(" ");

  Serial.print("Public Key X: ");
  for (int i = 0; i < 32; i++)
  {
    if (public_key_x.Ed[i] < 16) Serial.print("0");
    Serial.print(public_key_x.Ed[i], HEX);
    Serial.print(" ");
  }
  Serial.println(" ");
  Serial.print("Public Key Y: ");
  for (int i = 0; i < 32; i++)
  {
    if (public_key_y.Ed[i] < 16) Serial.print("0");
    Serial.print(public_key_y.Ed[i], HEX);
    Serial.print(" ");
  }
  Serial.println("\n"); // Extra newline

  if (result)
  {
    Serial.println("Signature is valid.");
  }
  else
  {
    Serial.println("Signature is invalid.");
  }
}
bool verify_signature(size_t message_len)
{
  field_element public_Nonce_t, public_Nonce_z = {{1}}, public_key_t, public_key_z = {{1}}, V1x, V1y, V1t, V1z, V2x, V2y, V2t, V2z, c_scalar;
  unsigned char c[64];
  binary_scalar_mul(&V1x, &V1y, &V1t, &V1z, Gx, Gy, Gt, Gz, signature, 64);
  mul(&public_Nonce_t, &public_Nonce_x, &public_Nonce_y);
  mul(&public_key_t, &public_key_x, &public_key_y);
  calculate_c(c, &public_key_x, message, message_len);
  modulo(&c_scalar, c);
  binary_scalar_mul(&V2x, &V2y, &V2t, &V2z, public_key_x, public_key_y, public_key_t, public_key_z, c_scalar.Ed, 32);
  mul(&V2t, &V2x, &V2y);
  V2z = {{1}};
  add_points(&V2x, &V2y, &V2t, &V2z, &public_Nonce_x, &public_Nonce_y, &public_Nonce_t, &public_Nonce_z);
  M_Inverse_Z(&V2z, &V2z);
  mul(&V2x, &V2x, &V2z);
  in_range(&V2x);
  mul(&V2y, &V2y, &V2z);
  in_range(&V2y);
  bool is_valid = true;
  for (int i = 0; i < 32; i++)
  {
    if (V1x.Ed[i] != V2x.Ed[i] || V1y.Ed[i] != V2y.Ed[i])
    {
      is_valid = false;
      break;
    }
  }
  return is_valid;
}

void binary_scalar_mul(field_element *xr, field_element *yr, field_element *tr, field_element *zr, field_element Gx, field_element Gy, field_element Gt, field_element Gz, const unsigned char *scalar, size_t scalar_size)
{
  *xr = Gx;
  *yr = Gy;
  *tr = Gt;
  *zr = Gz;
  signed char byteIndex;
  signed char bitIndex;
  for (signed char m = scalar_size; m >= 0; m--)
  {
    signed char n = 7;
    while (n >= 0)
    {
      if ((scalar[m] >> n) & 1)
      {
        byteIndex = m;
        bitIndex = n;
        m = -1;
        n = -1;
      }
      n--;
    }
  }
  signed char j = bitIndex - 1;
  for (signed char i = byteIndex; i >= 0; i--)
  {
    while (j >= 0)
    {
      unsigned char bit = (scalar[i] >> j) & 1;
      double_point(xr, yr, tr, zr);
      if (bit)
      {
        add_points(xr, yr, tr, zr, &Gx, &Gy, &Gt, &Gz);
      }
    j -= 1;
    }
  j = 7;
  }
  M_Inverse_Z(zr, zr);
  mul(xr, xr, zr);
  in_range(xr);
  mul(yr, yr, zr);
  in_range(yr);
}

void double_point(field_element *xr, field_element *yr, field_element *tr, field_element *zr)
{
  field_element A, B, C, D, E, F, G, H;
  square(&A, xr);
  square(&B, yr);
  square(&C, zr);
  add(&C, &C, &C);
  sub(&D, &prime, &A);
  add(&E, xr, yr);
  square(&E, &E);
  sub(&E, &E, &A);
  sub(&E, &E, &B);
  add(&G, &D, &B);
  sub(&F, &G, &C);
  sub(&H, &D, &B);
  mul(xr, &E, &F);
  mul(yr, &G, &H);
  mul(tr, &E, &H);
  mul(zr, &F, &G);
}
void add_points(field_element *xr, field_element *yr, field_element *tr, field_element *zr, const field_element *px, const field_element *py, const field_element *tz, const field_element *pz)
{
    field_element A, B, C, D, E, F, G, H;
    sub(&A, yr, xr);
    add(&B, py, px);
    mul(&A, &A, &B);
    add(&B, yr, xr);
    sub(&C, py, px);
    mul(&B, &B, &C);
    mul(&C, zr, tz);
    add(&C, &C, &C);
    mul(&D, tr, pz);
    add(&D, &D, &D);
    add(&E, &D, &C);
    sub(&F, &B, &A);
    add(&G, &B, &A);
    sub(&H, &D, &C);
    mul(xr, &E, &F);
    mul(yr, &G, &H);
    mul(tr, &E, &H);
    mul(zr, &F, &G);
}
void M_Inverse_Z(field_element *r, const field_element *x)
{
  field_element z2, z11, z2_10_0, z2_50_0, z2_100_0, t0, t1;
  unsigned char i;
  square(&z2,x);
  square(&t1,&z2);
  square(&t0,&t1);
  mul(&z2_10_0,&t0,x);
  mul(&z11,&z2_10_0,&z2);
  square(&t0,&z11);
  mul(&z2_10_0,&t0,&z2_10_0);
  square(&t0,&z2_10_0);
  square(&t1,&t0);
  square(&t0,&t1);
  square(&t1,&t0);
  square(&t0,&t1);
  mul(&z2_10_0,&t0,&z2_10_0);
  square(&t0,&z2_10_0);
  square(&t1,&t0);
  for (i = 2;i < 10;i += 2){ square(&t0,&t1); square(&t1,&t0); }
  mul(&z2_50_0,&t1,&z2_10_0);
  square(&t0,&z2_50_0);
  square(&t1,&t0);
  for (i = 2;i < 20;i += 2) { square(&t0,&t1); square(&t1,&t0); }
  mul(&t0,&t1,&z2_50_0);
  square(&t1,&t0);
  square(&t0,&t1);
  for (i = 2;i < 10;i += 2) { square(&t1,&t0); square(&t0,&t1); }
  mul(&z2_50_0,&t0,&z2_10_0);
  square(&t0,&z2_50_0);
  square(&t1,&t0);
  for (i = 2;i < 50;i += 2) { square(&t0,&t1); square(&t1,&t0); }
  mul(&z2_100_0,&t1,&z2_50_0);
  square(&t1,&z2_100_0);
  square(&t0,&t1);
  for (i = 2;i < 100;i += 2) { square(&t1,&t0); square(&t0,&t1); }
  mul(&t1,&t0,&z2_100_0);
  square(&t0,&t1);
  square(&t1,&t0);
  for (i = 2;i < 50;i += 2) { square(&t0,&t1); square(&t1,&t0); }
  mul(&t0,&t1,&z2_50_0);
  square(&t1,&t0);
  square(&t0,&t1);
  square(&t1,&t0);
  square(&t0,&t1);
  square(&t1,&t0);
  mul(r,&t1,&z11);
}

void in_range(field_element *r)
{
  unsigned char c;
  field_element rt;
  c = Ed_num_sub_prime(rt.Ed, r->Ed);
  flip_if(r,&rt,1-c);
}

void flip_if(field_element *r, const field_element *x, unsigned char b)
{
  unsigned char i;
  unsigned long mask = b;
  mask = -mask;
  for(i=0;i<32;i++)
  {
    r->Ed[i] ^= mask & (x->Ed[i] ^ r->Ed[i]);
  }
}

void mul(field_element *r, const field_element *x, const field_element *y)
{
  unsigned char t[64];
  cli();
  Ed_mul(t,x->Ed,y->Ed);
  sei();
  modulo(r,t);
}

void square(field_element *r, const field_element *x)
{
  unsigned char t[64];
  cli();
  Ed25519_square(t,x->Ed);
  sei();
  modulo(r,t);
}
void calculate_c(unsigned char* c, const field_element* public_key_x, const uint8_t* message, size_t message_len)
{
  SHA512 hashEngine;
  hashEngine.reset();
  hashEngine.update(public_key_x->Ed, 32);
  hashEngine.update(message, message_len);
  hashEngine.finalize(c, 64);
}