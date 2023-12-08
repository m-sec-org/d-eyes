package eventlog

import (
	"fmt"
	"math"
	"sync"
	"testing"
	"time"
)

func Test_time(t *testing.T)  {

	timeInUTC := time.Date(2018, 8, 30, 12, 34, 23, 0, time.UTC)
	fmt.Println(timeInUTC)
	fmt.Println(timeInUTC.In(time.Local))

	array := []int{10, 20, 30, 40}
	slice := make([]int, 6)
	n := copy(slice, array)
	fmt.Println(n,slice)
}

var wg sync.WaitGroup

func recv(c chan interface{}) {
	defer wg.Done()
	for true {
		time.Sleep(time.Second)
		ret := <-c
		if ret == "exit"{
			close(c)
			break
		}
		fmt.Println("接收成功", ret)
	}


}

func send(c chan interface{}) {
	defer wg.Done()
	for i:=0;i<10;i++{
		c <- i
	}
	c <- "exit"

	// time.Sleep(time.Second*10) // 写的协程结束，导致死锁

}

func Test_goroutine(t *testing.T) {

	ch := make(chan interface{})
	wg.Add(2)
	go recv(ch) // 启用goroutine从通道接收值
	go send(ch) // 启用goroutine从通道接收值

	wg.Wait()
	fmt.Println("end")

}

func Test_Hash(t *testing.T) {
	index := int((math.Pow(2,6) + 10)) % int(math.Pow(2,5))
	fmt.Println(index)
}


