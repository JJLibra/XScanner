package com.example.biometric;

import android.app.Activity;
import android.app.KeyguardManager;
import android.content.Context;
import android.hardware.fingerprint.FingerprintManager;
import android.os.Build;
import android.os.CancellationSignal;
import android.widget.Toast;

import androidx.annotation.NonNull;

import java.io.IOException;

public class BiometricPromptManager {
    private static final String TAG = "BiometricPromptManager";
    private IBiometricPromptImpl mImpl;
    private Activity mActivity;

    public interface OnBiometricIdentifyCallback {
        void onUsePassword();

        void onSucceeded() throws IOException;

        void onFailed();

        void onError(int code, String reason);

        void onCancel();

    }

    //判断API号实现不同的指纹方案
    public static BiometricPromptManager from(Activity activity) {
        return new BiometricPromptManager(activity);
    }

    public BiometricPromptManager(Activity activity) {
        mActivity = activity;
        if (isAboveApi28()) {
            mImpl = new BiometricPromptApi28(activity);
        } else if (isAboveApi23()) {
            mImpl = new BiometricPromptApi23(activity);
        }
    }

    private boolean isAboveApi28() {
        return Build.VERSION.SDK_INT >= Build.VERSION_CODES.P;
    }

    private boolean isAboveApi23() {
        return Build.VERSION.SDK_INT >= Build.VERSION_CODES.M;
    }

    public void authenticate(@NonNull OnBiometricIdentifyCallback callback) {
        mImpl.authenticate(new CancellationSignal(), callback);
    }

    public void authenticate(@NonNull CancellationSignal cancel,
                             @NonNull OnBiometricIdentifyCallback callback) {
        mImpl.authenticate(cancel, callback);
    }

    //判断系统中是否设置过指纹
    public boolean hasEnrolledFingerprints() {
        if (isAboveApi28()) {
            final FingerprintManager manager = mActivity.getSystemService(FingerprintManager.class);
            return manager != null && manager.hasEnrolledFingerprints();
        } else if (isAboveApi23()) {
            return ((BiometricPromptApi23) mImpl).hasEnrolledFingerprints();
        } else {
            Toast.makeText(mActivity, "请先在系统中设置指纹", Toast.LENGTH_LONG).show();
            return false;
        }
    }

    //判断硬件是否适配
    public boolean isHardwareDetected() {
        if (isAboveApi28()) {
            final FingerprintManager fm = mActivity.getSystemService(FingerprintManager.class);
            return fm != null && fm.isHardwareDetected();
        } else if (isAboveApi23()) {
            return ((BiometricPromptApi23) mImpl).isHardwareDetected();
        } else {
            Toast.makeText(mActivity, "系统不支持指纹识别", Toast.LENGTH_LONG).show();
            return false;
        }
    }

    //判断是否设置锁屏
    public boolean isKeyguardSecure() {
        KeyguardManager keyguardManager = (KeyguardManager) mActivity.getSystemService(Context.KEYGUARD_SERVICE);
        if (keyguardManager.isKeyguardSecure()) {
            return true;
        }

        return false;
    }

    //判断设备是否已支持指纹识别
    public boolean isBiometricPromptEnable() {
        return isAboveApi23()
                && hasEnrolledFingerprints()
                && isHardwareDetected()
                && isKeyguardSecure();
    }

    //判断APP中是否开启指纹认证
    public boolean isBiometricSettingEnabled() {
        return SPUtils.getBoolean(mActivity, SPUtils.KEY_BIOMETRIC_SWITCH_ENABLE, false);
    }

    //在APP中开启指纹认证
    public void setBiometricSettingEnable(boolean enable) {
        SPUtils.put(mActivity, SPUtils.KEY_BIOMETRIC_SWITCH_ENABLE, enable);
    }

}
