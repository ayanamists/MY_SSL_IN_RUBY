class N
    def initialize 
    end

    def nothing 
        yield i
    end
end

n = N.new
n.nothing do 
    puts "hjah"
end