/*
 * Copyright 2016 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"). You may not use this file except
 * in compliance with the License. A copy of the License is located at
 * 
 * http://aws.amazon.com/apache2.0
 * 
 * or in the "license" file accompanying this file. This file is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */

package com.amazonaws.encryptionsdk.internal;

import java.io.DataOutput;
import java.io.IOException;

import com.amazonaws.encryptionsdk.exception.ParseException;

/**
 * This class implements methods for parsing the primitives (
 * {@code byte, short, int, long}) in Java from a byte array.
 */
//@ non_null_by_default
public class PrimitivesParser {
    /**
     * Construct a long value using 8 bytes starting at the specified offset.
     * 
     * @param b
     *            the byte array to parse.
     * @param off
     *            the offset in the byte array to use when parsing.
     * @return the parsed long value.
     */
    //@ private normal_behavior
    //@   requires 0 <= off && off <= b.length - Long.BYTES;
    //@   ensures \result == Long.asLong(b[off],b[off+1],b[off+2],b[off+3],b[off+4],b[off+5],b[off+6],b[off+7]);
    //@ pure spec_public
    private static long getLong(final byte[] b, final int off) {
        return ((b[off + 7] & 0xFFL)) + ((b[off + 6] & 0xFFL) << 8) + ((b[off + 5] & 0xFFL) << 16)
                + ((b[off + 4] & 0xFFL) << 24) + ((b[off + 3] & 0xFFL) << 32) + ((b[off + 2] & 0xFFL) << 40)
                + ((b[off + 1] & 0xFFL) << 48) + (((long) b[off]) << 56);
    }

    /**
     * Construct an integer value using 4 bytes starting at the specified offset.
     * 
     * @param b
     *            the byte array containing the integer value.
     * @param off
     *            the offset in the byte array to use when parsing.
     * @return the constructed integer value.
     */
    //@ private normal_behavior
    //@   requires 0 <= off && off <= b.length - Integer.BYTES;
    //@   ensures \result == Integer.asInt(b[off],b[off+1],b[off+2],b[off+3]);
    //@ pure spec_public
    private static int getInt(final byte[] b, final int off) {
        return ((b[off + 3] & 0xFF)) + ((b[off + 2] & 0xFF) << 8) + ((b[off + 1] & 0xFF) << 16)
                + ((b[off] & 0xFF) << 24);
    }

    /**
     * Construct a short value using 4 bytes starting at the specified offset.
     * 
     * @param b
     *            the byte array containing the short value.
     * @param off
     *            the offset in the byte array to use when parsing.
     * @return the constructed short value.
     */
    //@ private normal_behavior
    //@   requires 0 <= off && off <= b.length - Short.BYTES;
    //@   ensures \result == Short.asShort(b[off],b[off+1]);
    //@ pure spec_public
    private static short getShort(final byte[] b, final int off) {
        return (short) ((b[off + 1] & 0xFF) + ((b[off] & 0xFF) << 8));
    }

    /**
     * Parse a long primitive type in the provided bytes. It looks for
     * 8 bytes in the provided bytes starting at the specified off.
     * 
     * <p>
     * If successful, it returns the value of the parsed long type. On failure,
     * it throws a parse exception.
     * 
     * @param b
     *            the byte array to parse.
     * @param off
     *            the offset in the byte array to use when parsing.
     * @return
     *         the parsed long value.
     * @throws ParseException
     *             if there are not sufficient bytes.
     */
    //@ public normal_behavior
    //@   requires 0 <= off && off <= b.length - Long.BYTES;
    //@   ensures \result == Long.asLong(b[off],b[off+1],b[off+2],b[off+3],b[off+4],b[off+5],b[off+6],b[off+7]);
    //@ also private exceptional_behavior
    //@   requires b.length - Long.BYTES < off;
    //@   signals_only ParseException;
    //@ pure
    public static long parseLong(final byte[] b, final int off) throws ParseException {
        final int size = Long.SIZE / Byte.SIZE;
        final int len = b.length - off;
        if (len >= size) {
            return getLong(b, off);
        } else {
            throw new ParseException("Not enough bytes to parse a long.");
        }
    }

    /**
     * Parse an integer primitive type in the provided bytes. It looks for
     * 4 bytes in the provided bytes starting at the specified off.
     * 
     * <p>
     * If successful, it returns the value of the parsed integer type. On
     * failure, it throws a parse exception.
     * 
     * @param b
     *            the byte array to parse.
     * @param off
     *            the offset in the byte array to use when parsing.
     * @return
     *         the parsed integer value.
     * @throws ParseException
     *             if there are not sufficient bytes.
     */
    //@ public normal_behavior
    //@   requires 0 <= off && off <= b.length - Integer.BYTES;
    //@   ensures \result == Integer.asInt(b[off],b[off+1],b[off+2],b[off+3]);
    //@ also private exceptional_behavior
    //@   requires b.length - Integer.BYTES < off;
    //@   signals_only ParseException;
    //@ pure
    public static int parseInt(final byte[] b, final int off) throws ParseException {
        final int size = Integer.SIZE / Byte.SIZE;
        final int len = b.length - off;
        if (len >= size) {
            return getInt(b, off);
        } else {
            throw new ParseException("Not enough bytes to parse an integer.");
        }
    }

    /**
     * Parse a short primitive type in the provided bytes. It looks for 2 bytes
     * in the provided bytes starting at the specified off.
     * 
     * <p>
     * If successful, it returns the value of the parsed short type. On failure,
     * it throws a parse exception.
     * 
     * @param b
     *            the byte array to parse.
     * @param off
     *            the offset in the byte array to use when parsing.
     * @return
     *         the parsed short value.
     * @throws ParseException
     *             if there are not sufficient bytes.
     */
    //@ public normal_behavior
    //@   requires 0 <= off && off <= b.length - Short.BYTES;
    //@   ensures \result == Short.asShort(b[off],b[off+1]);
    //@ also private exceptional_behavior
    //@   requires b.length - Short.BYTES < off;
    //@   signals_only ParseException;
    //@ pure
   public static short parseShort(final byte[] b, final int off) {
        final short size = Short.SIZE / Byte.SIZE;
        final int len = b.length - off;
        if (len >= size) {
            return getShort(b, off);
        } else {
            throw new ParseException("Not enough bytes to parse a short.");
        }
    }

    /**
     * Equivalent to {@link #parseShort(byte[], int)} except the 2 bytes are treated as an unsigned
     * value (and thus returned as an into to avoid overflow).
     */
   //@ public normal_behavior
   //@   requires 0 <= off && off <= b.length - Short.BYTES;
   //@   ensures \result == Short.asUnsignedToInt(Short.asShort(b[off], b[off+1]));
   //@ also private exceptional_behavior
   //@   requires b.length - Short.BYTES < off;
   //@   signals_only ParseException;
   //@ pure
    public static int parseUnsignedShort(final byte[] b, final int off) {
        final int signedResult = parseShort(b, off);
        if (signedResult >= 0) {
            return signedResult;
        } else {
            return Constants.UNSIGNED_SHORT_MAX_VAL + 1 + signedResult;
        }
    }

    /**
     * Writes 2 bytes containing the unsigned value {@code uShort} to {@code out}.
     */
    //@ public normal_behavior
    //@   requires 0 <= uShort && uShort < -Short.MIN_VALUE-Short.MIN_VALUE;
    //@//    assignable TODO ...
    //@//    ensures    TODO ...
    public static void writeUnsignedShort(final DataOutput out, final int uShort) throws IOException {
        if (uShort < 0 || uShort > Constants.UNSIGNED_SHORT_MAX_VAL) {
            throw new IllegalArgumentException("Unsigned shorts must be between 0 and "
                    + Constants.UNSIGNED_SHORT_MAX_VAL);
        }
        if (uShort < Short.MAX_VALUE) {
            out.writeShort(uShort);
        } else {
            out.writeShort(uShort - Constants.UNSIGNED_SHORT_MAX_VAL - 1);
        }
    }

    /**
     * Parse a single byte in the provided bytes. It looks for a byte in the
     * provided bytes starting at the specified off.
     * 
     * <p>
     * If successful, it returns the value of the parsed byte. On failure, it
     * throws a parse exception.
     * 
     * @param b
     *            the byte array to parse.
     * @param off
     *            the offset in the byte array to use when parsing.
     * @return
     *         the parsed byte value.
     * @throws ParseException
     *             if there are not sufficient bytes.
     */
    //@ public normal_behavior
    //@   requires 0 <= off && off <= b.length - Byte.BYTES;
    //@   ensures \result == b[off];
    //@ also private exceptional_behavior
    //@   requires b.length - Byte.BYTES < off;
    //@   signals_only ParseException;
    //@ pure
    public static byte parseByte(final byte[] b, final int off) {
        final int size = 1;
        final int len = b.length - off;
        if (len >= size) {
            return b[off];
        } else {
            throw new ParseException("Not enough bytes to parse a byte.");
        }
    }
//    
//    // OPENJML - CAUTION - A solver may not see this operation as commutative
//    //@ public normal_behavior
//    //@   requires len >= 0;
//    //@   requires 0 <= index1 && index1 <= bytes1.length - len;
//    //@   requires 0 <= index2 && index2 <= bytes2.length - len;
//    //@   ensures \result == (\forall int i; index1 <= i && i < index1 + len; bytes1[i] == bytes2[i-index1+index2]);
//    //@ model public static pure helper function boolean equalArrays(byte[] bytes1, int index1, byte[] bytes2, int index2, int len);
//    
//    //@ public normal_behavior
//    //@   ensures \result == (b >= 0 ? b : b + 256);
//    //@ model public static pure helper function int asUnsigned(byte b);
//    
//    //@ public normal_behavior
//    //@   ensures \result == (b >= 0 ? b : b + 256);
//    //@ model public static pure helper function long asUnsignedL(byte b) { return (b >= 0 ? b : b + 256); }
//    
//    //@ public normal_behavior
//    //@   ensures \result == (asUnsigned(b0)*256 + asUnsigned(b1));
//    //@   ensures 0 <= \result && \result < (-2)*Short.MIN_VALUE;
//    //@ model public static pure helper function int asUnsignedShort(byte b0, byte b1);
//    
//    //@ public normal_behavior
//    //@   ensures \result == (short)(b0*256 + asUnsigned(b1));
//    //@ model public static pure helper function short asShort(byte b0, byte b1);
//    
//    //@ public normal_behavior
//    //@   ensures \result == (b0*(0x100_0000) + asUnsigned(b1)*(0x10000) + asUnsigned(b2)*(0x100) + asUnsigned(b3));
//    //@ model public static pure helper function int asInt(byte b0, byte b1, byte b2, byte b3);
//
//    //@ public normal_behavior  // OPENJML FIXME - debug and cleanup
//    //@   ensures \result == (b0*(0x100_0000_0000_0000L) + asUnsignedL(b1)*(0x10000_0000_0000L) + asUnsignedL(b2)*(0x100_0000_0000L) + (\lbl SB3 (\lbl UB3 asUnsignedL(b3))*(0x10000_0000L)) + (\lbl UB4 asUnsignedL(b4))*(0x100_0000L) + asUnsignedL(b5)*(0x10000L) + asUnsignedL(b6)*(0x100L) + asUnsignedL(b7));
//    //@ model public static pure helper function long asLong(byte b0, byte b1, byte b2, byte b3, byte b4, byte b5, byte b6, byte b7);

}
