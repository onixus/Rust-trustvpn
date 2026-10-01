package org.rtrusttunnel.android;

import android.graphics.*;
import java.io.*;
import java.util.*;
import com.google.zxing.*;
import com.google.zxing.common.HybridBinarizer;

final class QrImport {
    static String decode(InputStream stream) throws Exception {
        byte[] bytes = ProfileVault.readBounded(stream, 12 * 1024 * 1024);
        Bitmap image = null;
        try {
            BitmapFactory.Options options = new BitmapFactory.Options(); options.inJustDecodeBounds = true;
            BitmapFactory.decodeByteArray(bytes, 0, bytes.length, options);
            if (options.outWidth < 1 || options.outHeight < 1 || (long)options.outWidth * options.outHeight > 100_000_000) throw new IOException();
            options.inJustDecodeBounds = false; options.inSampleSize = 1;
            while (Math.max(options.outWidth, options.outHeight) / options.inSampleSize > 2048) options.inSampleSize *= 2;
            image = BitmapFactory.decodeByteArray(bytes, 0, bytes.length, options);
            if (image == null) throw new IOException();
            int width = image.getWidth(), height = image.getHeight(); int[] pixels = new int[width * height];
            try {
                image.getPixels(pixels, 0, width, 0, 0, width, height);
                LuminanceSource source = new RGBLuminanceSource(width, height, pixels);
                Map<DecodeHintType,Object> hints = new EnumMap<>(DecodeHintType.class);
                hints.put(DecodeHintType.POSSIBLE_FORMATS, Collections.singletonList(BarcodeFormat.QR_CODE)); hints.put(DecodeHintType.TRY_HARDER, true);
                try { return new MultiFormatReader().decode(new BinaryBitmap(new HybridBinarizer(source)), hints).getText(); }
                catch (NotFoundException dark) { return new MultiFormatReader().decode(new BinaryBitmap(new HybridBinarizer(source.invert())), hints).getText(); }
            } finally { Arrays.fill(pixels, 0); }
        } finally { Arrays.fill(bytes, (byte)0); if (image != null) image.recycle(); }
    }
}
