<?php

use App\Http\Controllers\AuthContoller;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider and all of them will
| be assigned to the "api" middleware group. Make something great!
|
*/
Route::post("/register",[AuthContoller::class,"register"]);
Route::post("/login",[AuthContoller::class,"login"]);

Route::middleware('auth:sanctum')->group(function (){
    Route::post("/logout",[AuthContoller::class, "logout"]);
    Route::get("/user",[AuthContoller::class,"user"]);
});
