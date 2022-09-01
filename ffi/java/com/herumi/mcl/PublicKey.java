/* ----------------------------------------------------------------------------
 * This file was automatically generated by SWIG (http://www.swig.org).
 * Version 4.0.2
 *
 * Do not make changes to this file unless you know what you are doing--modify
 * the SWIG interface file instead.
 * ----------------------------------------------------------------------------- */

package com.herumi.mcl;

public class PublicKey {
  private transient long swigCPtr;
  protected transient boolean swigCMemOwn;

  protected PublicKey(long cPtr, boolean cMemoryOwn) {
    swigCMemOwn = cMemoryOwn;
    swigCPtr = cPtr;
  }

  protected static long getCPtr(PublicKey obj) {
    return (obj == null) ? 0 : obj.swigCPtr;
  }

  @SuppressWarnings("deprecation")
  protected void finalize() {
    delete();
  }

  public synchronized void delete() {
    if (swigCPtr != 0) {
      if (swigCMemOwn) {
        swigCMemOwn = false;
        ElgamalJNI.delete_PublicKey(swigCPtr);
      }
      swigCPtr = 0;
    }
  }

  public String toStr() {
    return ElgamalJNI.PublicKey_toStr(swigCPtr, this);
  }

  public String toString() {
    return ElgamalJNI.PublicKey_toString(swigCPtr, this);
  }

  public void fromStr(String str) {
    ElgamalJNI.PublicKey_fromStr(swigCPtr, this, str);
  }

  public void save(String fileName) {
    ElgamalJNI.PublicKey_save(swigCPtr, this, fileName);
  }

  public void load(String fileName) {
    ElgamalJNI.PublicKey_load(swigCPtr, this, fileName);
  }

  public void enc(CipherText c, int m) {
    ElgamalJNI.PublicKey_enc__SWIG_0(swigCPtr, this, CipherText.getCPtr(c), c, m);
  }

  public void enc(CipherText c, String str) {
    ElgamalJNI.PublicKey_enc__SWIG_1(swigCPtr, this, CipherText.getCPtr(c), c, str);
  }

  public void rerandomize(CipherText c) {
    ElgamalJNI.PublicKey_rerandomize(swigCPtr, this, CipherText.getCPtr(c), c);
  }

  public void add(CipherText c, int m) {
    ElgamalJNI.PublicKey_add__SWIG_0(swigCPtr, this, CipherText.getCPtr(c), c, m);
  }

  public void add(CipherText c, String str) {
    ElgamalJNI.PublicKey_add__SWIG_1(swigCPtr, this, CipherText.getCPtr(c), c, str);
  }

  public PublicKey() {
    this(ElgamalJNI.new_PublicKey(), true);
  }

}
