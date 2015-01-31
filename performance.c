#include <stdio.h>
#include <string.h>
#include "aes.h"
#include "performance.h"
#define MAX 50


double calculateMean(double *opTime, int size)
{
	double mean = 0;
	int i = 0;
	for(i = 0; i<size; i++)
		mean+= opTime[i];
	
	return (mean/size);
}

double calculateMedian(double *opTime, int max)
{
	int i =0;
	double medianValue;
	printf("Calculating median \n");
	partition(opTime, 0 ,max-1);
	medianValue = opTime[max/2];
	return medianValue;
}


 void partition(double arr[],int low,int high)
{

    int mid;

    if(low<high){
         mid=(low+high)/2;
         partition(arr,low,mid);
         partition(arr,mid+1,high);
         mergeSort(arr,low,mid,high);
    }
}

void mergeSort(double arr[],int low,int mid,int high)
{
    int i,m,k,l;
    double temp[MAX];

    l=low;
    i=low;
    m=mid+1;

    while((l<=mid)&&(m<=high)){

         if(arr[l]<=arr[m]){
             temp[i]=arr[l];
             l++;
         }
         else{
             temp[i]=arr[m];
             m++;
         }
         i++;
    }

    if(l>mid){
         for(k=m;k<=high;k++){
             temp[i]=arr[k];
             i++;
         }
    }
    else{
         for(k=l;k<=mid;k++){
             temp[i]=arr[k];
             i++;
         }
    }
   
    for(k=low;k<=high;k++){
         arr[k]=temp[k];
    }
}

double medianCalculate(double x[], int n) 
{
    double temp;
    int i, j;
    // the following two loops sort the array x in ascending order
    for(i=0; i<n-1; i++) {
        for(j=i+1; j<n; j++) {
            if(x[j] < x[i]) {
                // swap elements
                temp = x[i];
                x[i] = x[j];
                x[j] = temp;
            }
        }
    }
 
    if(n%2==0) {
        // if there is an even number of elements, return mean of the two elements in the middle
        return (double)((x[n/2] + x[n/2 - 1]) / 2.0);
    } else {
        // else return the element in the middle
        return (double)x[n/2];
    }
}
