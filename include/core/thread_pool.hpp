/**
 * @file thread_pool.hpp
 * @brief A robust, header-only Thread Pool implementation.
 * Allows queuing arbitrary tasks and processing them with a fixed set of worker threads.
 * Prevents system crashes caused by thread exhaustion (std::async spawning unlimited threads).
 */

#pragma once

#include <vector>
#include <queue>
#include <memory>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <future>
#include <functional>
#include <stdexcept>
#include <atomic>

namespace dais::core::utils {

    class ThreadPool {
    public:
        // Constructor: Launch a fixed number of workers
        explicit ThreadPool(size_t threads = std::thread::hardware_concurrency()) 
            : stop(false) 
        {
            // If hardware_concurrency returns 0 (error), fallback to 4
            if (threads == 0) threads = 4;

            for(size_t i = 0; i < threads; ++i)
                workers.emplace_back([this] {
                    while(true) {
                        std::function<void()> task;

                        {
                            std::unique_lock<std::mutex> lock(this->queue_mutex);
                            this->condition.wait(lock, [this]{ return this->stop || !this->tasks.empty(); });
                            
                            if(this->stop && this->tasks.empty())
                                return;
                            
                            task = std::move(this->tasks.front());
                            this->tasks.pop();
                        }

                        task();
                    }
                });
        }

        // Add new work item to the pool
        template<class F, class... Args>
        auto enqueue(F&& f, Args&&... args) 
            -> std::future<typename std::invoke_result<F, Args...>::type>
        {
            using return_type = typename std::invoke_result<F, Args...>::type;

            auto task = std::make_shared<std::packaged_task<return_type()>>(
                std::bind(std::forward<F>(f), std::forward<Args>(args)...)
            );
            
            std::future<return_type> res = task->get_future();
            {
                std::unique_lock<std::mutex> lock(queue_mutex);

                // Don't allow enqueueing after stopping
                if(stop)
                    throw std::runtime_error("enqueue on stopped ThreadPool");

                tasks.emplace([task](){ (*task)(); });
            }
            condition.notify_one();
            return res;
        }

        // Destructor: Join all threads
        ~ThreadPool() {
            {
                std::unique_lock<std::mutex> lock(queue_mutex);
                stop = true;
            }
            condition.notify_all();
            for(std::thread &worker: workers)
                worker.join();
        }

    private:
        // Need to keep track of threads so we can join them
        std::vector<std::thread> workers;
        // The task queue
        std::queue<std::function<void()>> tasks;
        
        // Synchronization
        std::mutex queue_mutex;
        std::condition_variable condition;
        bool stop;
    };
}