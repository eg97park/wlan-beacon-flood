#!/bin/bash
sudo ifconfig wlp45s0 down;
sudo iwconfig wlp45s0 mode monitor;
sudo ifconfig wlp45s0 up;