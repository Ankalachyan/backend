<?php

namespace App\Http\Controllers;

use App\Http\Requests\LoginRequest;
use App\Http\Requests\RegisterRequest;
use App\Http\Resources\UserResource;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Storage;
use Illuminate\Support\Str;

class AuthContoller extends Controller
{
    public function register(RegisterRequest $request)
    {
        $data = $request->validated();
        $imageName = Str::random(32).".".$data["image"]->getClientOriginalExtension();
        $user = User::create([
            "name" => $data["name"],
            "email" => $data['email'],
            "image"=>$imageName,
            "password" => Hash::make($data["password"])
        ]);
        Storage::disk("public")->put($imageName, file_get_contents($data["image"]));
        $token = $user->createToken('auth_token')->plainTextToken;
        $cookie = cookie("token", $token, 60 * 24);
        return response()->json([
            "user" => new UserResource($user),
        ])->withCookie($cookie);
    }
    public function login(LoginRequest $request)
    {
        $data = $request->validated();
        $user = User::where("email", $data["email"])->first();
        if (!$user || !Hash::check($data["password"], $user->password)) {
            return response()->json([
                "message" => "Email or password is wrong"
            ], 401);
        }
        $token = $user->createToken('auth_token')->plainTextToken;
        $cookie = cookie("token", $token, 60 * 24);
        return response()->json([
            $user = new UserResource($user),
        ])->withCookie($cookie);
    }
    public function logout(Request $request)
    {
        $request->user()->currentAccessToken()->delete();
        $cookie = cookie()->forget("token");
        return response()->json([
            "message" => "You've been logged out"
        ])->withCookie($cookie);
    }
    public function user(Request $request){
        return new UserResource($request->user());
    }
}
